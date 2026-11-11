package com.tracelink.appsec.watchtower.core.assistant;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import com.fasterxml.jackson.databind.JsonNode;
import com.tracelink.appsec.watchtower.core.process.*;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.*;
import com.tracelink.appsec.watchtower.core.scan.repository.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

/** Each operation downloads exactly its pin; source remains local and is deleted in finally. */
@Service
public class AssistantSourceTools {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(AssistantSourceTools.class);
    public static final Set<String> GRANTS = Set.of("Assistant Source Read", "Repository Settings View", "Scan Results View");
    public static final Set<String> NAMES = Set.of("list_repositories", "resolve_repository_commit", "list_source_files",
            "read_source_file", "search_source", "source_outline", "search_source_symbols", "source_references");
    private static final int FILE_BYTES = 1024 * 1024;
    private static final long TTL = 15 * 60_000L;
    private final AssistantAccess access;
    private final RepositoryRepository repositories;
    private final ApiIntegrationService integrations;
    private final ProcessRunner processes;
    private final String python;
    private final Path directory;
    private final AssistantSecretFindings secrets;

    public AssistantSourceTools(AssistantAccess access, RepositoryRepository repositories,
            ApiIntegrationService integrations, ProcessRunner processes, AssistantSecretFindings secrets,
            @Value("${watchtower.assistant.source-python:/opt/watchtower/pythonvenv/bin/python3}") String python,
            @Value("${watchtower.assistant.source-directory:${java.io.tmpdir}/watchtower-assistant-source}") String directory) {
        this.access = access; this.repositories = repositories; this.integrations = integrations;
        this.processes = processes; this.python = python; this.directory = Path.of(directory); this.secrets = secrets;
    }

    public void scope(String owner, JsonNode args) {
        for (String grant : GRANTS) access.require(owner, grant);
        if (args.has("repo_id")) repository(args.path("repo_id").asLong());
    }

    public Object invoke(String owner, String name, JsonNode args) {
        scope(owner, args);
        if (name.equals("list_repositories")) {
            int offset = args.path("offset").asInt();
            var page = repositories.findAll(PageRequest.of(offset / 20, 20, org.springframework.data.domain.Sort.by("id")));
            var rows = page.stream().skip(offset % 20)
                    .filter(r -> integration(r) != null).map(r -> Map.of("repo_id", r.getId(), "integration", r.getApiLabel(),
                            "repository", r.getRepoName(), "default_branch", Objects.toString(r.getDefaultBranch(), "unknown"))).toList();
            return Map.of("repositories", rows, "offset", offset, "more", page.hasNext(), "next_offset", (offset / 20 + 1) * 20);
        }
        RepositoryEntity repo = repository(args.path("repo_id").asLong());
        IScmApi api = integration(repo);
        if (name.equals("resolve_repository_commit")) {
            String branch = args.path("branch").asText();
            if (branch.isBlank() || branch.length() > 200 || branch.indexOf('\0') >= 0) throw new IllegalArgumentException("Invalid branch");
            var head = api.getBranch(repo.getRepoName(), branch).orElseThrow(() -> new IllegalArgumentException("Branch unavailable"));
            pin(head.commitHash());
            return Map.of("repo_id", repo.getId(), "branch", branch, "commit", head.commitHash(), "resolved_at", System.currentTimeMillis(),
                    "limitation", "This explicitly resolves the branch now. All source requests must use the returned full commit; recovery never resolves HEAD again.");
        }
        String commit = args.path("commit").asText(); pin(commit);
        AssistantSecretFindings.Lines masked = name.equals("list_source_files") ? null : secretLines(repo);
        return workspace(owner, repo, api, commit, root -> {
            Object result = switch (name) {
                case "list_source_files" -> files(root, args.path("offset").asInt());
                case "read_source_file" -> read(root, args, masked);
                case "search_source" -> search(root, args.path("query").asText(), masked);
                case "source_outline", "search_source_symbols", "source_references" -> outline(root, name, args, masked);
                default -> throw new IllegalArgumentException("Unknown source tool");
            };
            scope(owner, args); // Revocation during download/parsing must block disclosure.
            return Map.of("repo_id", repo.getId(), "repository", repo.getRepoName(), "commit", commit,
                    "evidence", result, "framework_knowledge", "Source/sink/sanitizer behavior remains uncertain unless approved knowledge covers this exact scope.");
        });
    }

    /** A repository and its live SCM integration, after the caller's current source grants. */
    public record Target(RepositoryEntity repository, IScmApi api) { }
    public Target target(String owner, long repositoryId) {
        for (String grant : GRANTS) access.require(owner, grant);
        var repo = repository(repositoryId);
        return new Target(repo, integration(repo));
    }
    private RepositoryEntity repository(long id) {
        if (id <= 0) throw new IllegalArgumentException("Invalid repository");
        var repo = repositories.findById(id).orElseThrow(() -> new AccessDeniedException("Repository unavailable"));
        if (integration(repo) == null) throw new AccessDeniedException("Repository integration unavailable");
        return repo;
    }
    private IScmApi integration(RepositoryEntity repo) {
        var entity = integrations.findByLabel(repo.getApiLabel());
        return entity != null && entity.createApi() instanceof IScmApi api ? api : null;
    }
    /** Lines where any engine recorded a secret are never sent; if that cannot be checked, nothing is. */
    private AssistantSecretFindings.Lines secretLines(RepositoryEntity repo) {
        try { return secrets.lines(repo); }
        catch (AssistantSecretFindings.Unavailable e) {
            LOG.warn("Source withheld from the assistant for repository {}: {}", repo.getId(), e.getMessage());
            throw new IllegalArgumentException("Source withheld: recorded secret findings could not be checked");
        }
    }
    /** Masking compares the resolved repository-relative path, never the caller's spelling of it. */
    private static String key(Path root, Path file) { return root.relativize(file.normalize()).toString().replace('\\', '/'); }
    static String maskedLine(String engine) { return "[REDACTED: secret detected by " + engine + "]"; }
    private static void pin(String commit) { if (!commit.matches("[a-f0-9]{40}")) throw new IllegalArgumentException("Use the full immutable commit hash"); }

    private Object workspace(String owner, RepositoryEntity repo, IScmApi api, String commit, Function<Path, Object> operation) {
        try {
            return com.tracelink.appsec.watchtower.core.scan.code.scm.api.PinnedSource.open(api, repo.getRepoName(), commit, directory, "request-", SourceDownloadLimits.ASSISTANT, root -> {
                for (String grant : GRANTS) access.require(owner, grant);
                return operation.apply(root);
            });
        } catch (IOException e) {
            throw new IllegalArgumentException("Pinned source unavailable or exceeds limits; the commit was not changed");
        }
    }

    private List<Path> readableFiles(Path root) throws IOException {
        try (var paths = Files.walk(root)) {
            return paths.filter(p -> Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
                    .filter(p -> permitted(root.relativize(p).toString().replace('\\', '/'))).sorted().toList();
        }
    }
    private Object files(Path root, int offset) {
        try { var paths = readableFiles(root); return Map.of("files", paths.stream().skip(offset).limit(20).map(p -> root.relativize(p).toString()).toList(),
                "offset", offset, "more", paths.size() > offset + 20, "limitation", "Credential files, .git and extracted binary content are excluded."); }
        catch (IOException e) { throw new IllegalArgumentException("Source listing unavailable"); }
    }
    private static boolean permitted(String relative) {
        return Arrays.stream(relative.split("/")).noneMatch(part -> part.equals(".git") || part.equals(".env") || part.startsWith(".env.")
                || part.endsWith(".pem") || part.endsWith(".key") || part.endsWith(".p12") || part.endsWith(".pfx"));
    }
    private Path path(Path root, String relative) {
        if (relative.isBlank() || relative.length() > 255 || relative.contains("\\") || relative.indexOf('\0') >= 0
                || relative.startsWith("/") || relative.contains(":") || !permitted(relative)) throw new IllegalArgumentException("Invalid repository-relative path");
        Path path = root.resolve(relative).normalize();
        if (!path.startsWith(root) || Arrays.asList(relative.split("/", -1)).stream().anyMatch(part -> part.equals("..") || part.equals(".") || part.isEmpty())) throw new IllegalArgumentException("Path escapes repository");
        for (Path p = path; p != null && p.startsWith(root); p = p.getParent()) if (Files.isSymbolicLink(p)) throw new IllegalArgumentException("Linked source unavailable");
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Source file unavailable");
        return path;
    }
    private String text(Path path) throws IOException {
        if (Files.size(path) > FILE_BYTES) throw new IOException("File limit");
        try (var input = Files.newInputStream(path)) {
            byte[] bytes = input.readNBytes(FILE_BYTES + 1);
            if (bytes.length > FILE_BYTES) throw new IOException("File limit");
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            if (text.indexOf('\0') >= 0) throw new IOException("Binary file");
            return text;
        }
    }
    private Object read(Path root, JsonNode args, AssistantSecretFindings.Lines masked) {
        int first = args.path("start_line").asInt(), count = args.path("line_count").asInt();
        if (first < 1 || first > 100_000 || count < 1 || count > 200) throw new IllegalArgumentException("Read range limit");
        String relative = args.path("path").asText();
        try { Path file = path(root, relative); String key = key(root, file);
            var lines = AssistantText.redactSource(text(file)).lines().toList(); var result = new ArrayList<Object>();
            for (int i = first - 1; i < Math.min(lines.size(), first - 1 + count); i++) {
                String engine = masked.engine(key, i + 1);
                if (engine != null) { result.add(Map.of("line", i + 1, "text", maskedLine(engine), "truncated", false)); continue; }
                result.add(Map.of("line", i + 1, "text", AssistantText.redact(lines.get(i).substring(0, Math.min(2000, lines.get(i).length()))), "truncated", lines.get(i).length() > 2000));
            }
            return Map.of("path", args.path("path").asText(), "lines", result, "more", lines.size() > first - 1 + count);
        } catch (IOException e) { throw new IllegalArgumentException("Source read unavailable or exceeds limits"); }
    }
    private Object search(Path root, String query, AssistantSecretFindings.Lines masked) {
        if (query.isBlank() || query.length() > 100) throw new IllegalArgumentException("Literal query required");
        List<Object> matches = new ArrayList<>(); long bytes = 0; int inspected = 0, skipped = 0; boolean truncated = false;
        try {
            for (Path file : readableFiles(root)) {
                if (++inspected > 1000 || (bytes += Files.size(file)) > 16L * FILE_BYTES) { truncated = true; break; }
                String content;
                try { content = text(file); } catch (IOException e) { skipped++; continue; }
                var lines = content.lines().toList();
                String relative = key(root, file);
                // A match on a secret line would let the model confirm a guessed value, so it is skipped.
                for (int i = 0; i < lines.size(); i++) if (lines.get(i).contains(query) && masked.engine(relative, i + 1) == null) {
                    matches.add(Map.of("path", relative, "line", i + 1));
                    if (matches.size() >= 50) { truncated = true; break; }
                }
                if (truncated) break;
            }
        } catch (IOException e) { throw new IllegalArgumentException("Source search unavailable"); }
        return Map.of("matches", matches, "literal", true, "truncated", truncated, "skipped_files", skipped,
                "limitation", "Bounded literal search; absence is not proof that a behavior or vulnerability is absent. Lines where a secret was recorded are never searched.");
    }
    private Object outline(Path root, String name, JsonNode args, AssistantSecretFindings.Lines masked) {
        String relative = args.path("path").asText(); Path source = path(root, relative);
        String extension = relative.substring(relative.lastIndexOf('.') + 1);
        String language = switch (extension) { case "java" -> "java"; case "py" -> "python"; case "js", "jsx" -> "javascript"; case "ts" -> "typescript"; case "tsx" -> "tsx"; default -> null; };
        if (language == null) return Map.of("unsupported", true, "limitation", "No pinned Tree-sitter grammar for this language.");
        String operation = name.equals("source_outline") ? "outline" : name.equals("source_references") ? "references" : "symbols";
        String symbol = args.path("symbol").asText("");
        if (!operation.equals("outline") && (symbol.isBlank() || symbol.length() > 100)) throw new IllegalArgumentException("Symbol required");
        Path script = root.getParent().resolve("source_outline.py");
        try {
            text(source); // bounded valid UTF-8 before passing to the native parser
            try (var input = new ClassPathResource("assistant/source_outline.py").getInputStream()) { Files.copy(input, script); }
            var result = processes.run(new ProcessRequest(List.of(python, "-I", script.toString(), source.toString(), language, operation, symbol),
                    root.getParent(), Duration.ofSeconds(10), 128 * 1024, Map.of()));
            if (!result.isSuccess() || result.stdoutTruncated() || result.stderrTruncated()) return Map.of("unavailable", true, "limitation", "Pinned Tree-sitter parser failed or reached its limit.");
            return withoutSecretLines(AssistantState.mapper().readTree(result.stdout()), key(root, source), masked);
        } catch (IOException | ProcessExecutionException e) { return Map.of("unavailable", true, "limitation", "Pinned Tree-sitter parser unavailable."); }
    }

    /** Drops outline entries that sit on a line where a secret was recorded. */
    private static JsonNode withoutSecretLines(JsonNode outline, String relative, AssistantSecretFindings.Lines masked) {
        if (!(outline instanceof com.fasterxml.jackson.databind.node.ObjectNode object)) return outline;
        var copy = object.deepCopy();
        copy.fields().forEachRemaining(field -> {
            if (!field.getValue().isArray()) return;
            var kept = AssistantState.mapper().createArrayNode();
            for (var entry : field.getValue()) if (!entry.has("line") || masked.engine(relative, entry.path("line").asInt()) == null) kept.add(entry);
            field.setValue(kept);
        });
        return copy;
    }

    /** R6: a bounded window around one line at a pinned commit, secret lines masked, for advisory assessment. */
    public record Window(int first, List<Map<String, Object>> lines, boolean targetLineMasked) { }
    public Window window(String owner, RepositoryEntity repo, String commit, String relative, int line, int radius) {
        for (String grant : GRANTS) access.require(owner, grant);
        pin(commit);
        if (line < 1 || line > 100_000 || radius < 0 || radius > 100) throw new IllegalArgumentException("Window limit");
        IScmApi api = integration(repo);
        if (api == null) throw new IllegalArgumentException("Repository integration unavailable");
        AssistantSecretFindings.Lines masked = secretLines(repo);
        return (Window) workspace(owner, repo, api, commit, root -> {
            try {
                Path file = path(root, relative); String key = key(root, file);
                var lines = AssistantText.redactSource(text(file)).lines().toList();
                if (line > lines.size()) throw new IllegalArgumentException("Line outside the file at this commit");
                int first = Math.max(1, line - radius), last = Math.min(lines.size(), line + radius);
                List<Map<String, Object>> result = new ArrayList<>();
                for (int i = first; i <= last; i++) {
                    String engine = masked.engine(key, i), value = lines.get(i - 1);
                    result.add(Map.of("line", i, "text", engine != null ? maskedLine(engine) : AssistantText.redact(value.substring(0, Math.min(200, value.length())))));
                }
                return new Window(first, List.copyOf(result), masked.engine(key, line) != null);
            } catch (IOException e) { throw new IllegalArgumentException("Source read unavailable or exceeds limits"); }
        });
    }

    /**
     * One picked file as the AI review sees it. {@code lines} are the text with recorded secret lines replaced by a
     * mask; {@code maskedLines} says which, so nothing is ever reported on them. {@code skipped} is a plain reason
     * when the file could not be read, and then there are no lines.
     */
    /** The most files one review reads from a single download (the AI review's own pick limit is the same). */
    public static final int MAX_REVIEW_FILES = 200;
    public record ReviewFile(String path, List<String> lines, int totalLines, boolean cut, Set<Integer> maskedLines, String skipped) {
        public boolean readable() { return skipped == null; }
    }

    /**
     * The files an engineer picked, read from one pinned download: secret lines masked, long files and lines cut,
     * and a file that cannot be read left out with a reason instead of failing the others. Nothing is kept.
     */
    @SuppressWarnings("unchecked")
    public List<ReviewFile> reviewFiles(String owner, RepositoryEntity repo, String commit, List<String> paths, int maxLines, int maxBytes) {
        for (String grant : GRANTS) access.require(owner, grant);
        pin(commit);
        if (paths == null || paths.isEmpty() || paths.size() > MAX_REVIEW_FILES || maxLines < 1 || maxLines > 5000 || maxBytes < 1 || maxBytes > FILE_BYTES) throw new IllegalArgumentException("Review read limit");
        IScmApi api = integration(repo);
        if (api == null) throw new IllegalArgumentException("Repository integration unavailable");
        AssistantSecretFindings.Lines masked = secretLines(repo);
        return (List<ReviewFile>) workspace(owner, repo, api, commit, root -> {
            List<ReviewFile> files = new ArrayList<>();
            for (String relative : paths) {
                try {
                    Path file = path(root, relative); String key = key(root, file);
                    var all = AssistantText.redactSource(text(file)).lines().toList();
                    List<String> kept = new ArrayList<>(); Set<Integer> maskedLines = new TreeSet<>(); int bytes = 0; boolean cut = false;
                    for (int i = 0; i < all.size(); i++) {
                        String engine = masked.engine(key, i + 1);
                        String value = engine != null ? maskedLine(engine) : AssistantText.redact(all.get(i).substring(0, Math.min(400, all.get(i).length())));
                        bytes += value.getBytes(StandardCharsets.UTF_8).length + 1;
                        if (kept.size() >= maxLines || bytes > maxBytes) { cut = true; break; }
                        if (engine != null) maskedLines.add(i + 1);
                        kept.add(value);
                    }
                    files.add(new ReviewFile(key, List.copyOf(kept), all.size(), cut, Set.copyOf(maskedLines), null));
                } catch (IllegalArgumentException | IOException e) {
                    files.add(new ReviewFile(relative, List.of(), 0, false, Set.of(), "It could not be read at this commit."));
                }
            }
            return List.copyOf(files);
        });
    }

    /**
     * The repository-relative paths of the files at a pinned commit that {@code wanted} accepts, in path order, at most
     * {@code limit}. Only names are returned, never contents; credential files and links are not listed.
     */
    @SuppressWarnings("unchecked")
    public List<String> sourceFiles(String owner, RepositoryEntity repo, String commit, java.util.function.Predicate<String> wanted, int limit) {
        for (String grant : GRANTS) access.require(owner, grant);
        pin(commit);
        if (limit < 1 || limit > 5000) throw new IllegalArgumentException("Listing limit");
        IScmApi api = integration(repo);
        if (api == null) throw new IllegalArgumentException("Repository integration unavailable");
        return (List<String>) workspace(owner, repo, api, commit, root -> {
            try {
                return readableFiles(root).stream().map(p -> key(root, p)).filter(wanted).limit(limit).toList();
            } catch (IOException e) {
                throw new IllegalArgumentException("Source listing unavailable");
            }
        });
    }

    /** Every pod cleans its own interrupted downloads even while assistant chat is disabled. */
    @Scheduled(fixedDelay = 60_000)
    public void cleanup() {
        try { com.tracelink.appsec.watchtower.core.scan.code.scm.api.PinnedSource.sweep(directory, "request-", TTL); }
        catch (IOException e) { LOG.warn("Temporary assistant source cleanup failed; retrying on the next maintenance tick"); }
    }
}
