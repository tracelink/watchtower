package com.tracelink.appsec.module.awssecurity;

import java.io.*;
import java.util.*;
import java.util.zip.*;
import org.springframework.stereotype.Service;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoReportStore;
import com.tracelink.appsec.module.awssecurity.AwsSecurityArtifact.Occurrence;

@Service
public class AwsSecurityImporter {
    static final int MAX_FINDINGS = 100000, PAGE_SIZE = 100, MAX_PAGE_BYTES = 2 * 1024 * 1024;
    private static final ObjectMapper JSON = new ObjectMapper();
    private final AwsSecurityClientGateway gateway;
    private final RepoReportStore store;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private AwsSecurityEvidencePolicy evidencePolicy = new AwsSecurityEvidencePolicy("", "");
    private final AwsSecurityFindingMapper mapper = new AwsSecurityFindingMapper();
    public AwsSecurityImporter(AwsSecurityClientGateway gateway, RepoReportStore store) { this.gateway = gateway; this.store = store; }
    public boolean sharedArtifacts() { return store.isShared(); }
    public static class ImportLimitExceeded extends IOException {
        final int returned; final String bound;
        ImportLimitExceeded(int returned, String bound) { super("Import bound exceeded: " + bound); this.returned = returned; this.bound = bound; }
    }
    public record Imported(String key, AwsSecurityArtifact manifest) { }
    public record ChangedFile(String file, List<Integer> lines) { }
    public String writeDiffIndex(String runId, byte[] patch, Runnable ownership) throws IOException {
        var parsed = com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile.parseMultiFileDiff(new ByteArrayInputStream(patch), runId);
        var records = parsed.entrySet().stream().map(e -> new ChangedFile(e.getKey(), e.getValue().changedLines())).toList();
        if (JSON.writeValueAsBytes(records).length > MAX_PAGE_BYTES) throw new IOException("Diff line index exceeds bound");
        String key = "reports/aws-security/" + runId + "/inputs/" + UUID.randomUUID() + ".json.gz";
        ownership.run(); store.put(key, encode(records), "application/gzip"); return key;
    }
    public String writeSourceIndex(String runId, String commit, AwsSecurityInputStore.Archive archive, Runnable ownership) throws IOException {
        var index = new AwsSecuritySourceIndex(commit, archive.sha256(), archive.index(), evidencePolicy.sourceRiskTypes(), evidencePolicy.webAppUrl());
        if (JSON.writeValueAsBytes(index).length > MAX_PAGE_BYTES) throw new IOException("Source index exceeds bound");
        String key = "reports/aws-security/" + runId + "/inputs/" + UUID.randomUUID() + ".json.gz";
        ownership.run(); store.put(key, encode(index), "application/gzip"); return key;
    }
    public AwsSecuritySourceIndex sourceIndex(AwsSecurityRun run) throws IOException {
        if (run.sourceIndexKey == null) return null;
        if (!run.sourceIndexKey.startsWith("reports/aws-security/" + run.id + "/inputs/")) throw new IOException("Invalid source linkage");
        var index = decode(store.get(run.sourceIndexKey).orElseThrow(() -> new IOException("Source index unavailable")), AwsSecuritySourceIndex.class);
        if (!Objects.equals(run.sourceSha, index.archiveSha256()) || !Objects.equals(AwsSecuritySnapshot.decode(run.snapshotJson).context().commit(), index.commit())) throw new IOException("Source identity mismatch");
        return index;
    }
    public Imported importAll(AwsSecurityRun run, Runnable ownership) throws IOException {
        var snapshot = AwsSecuritySnapshot.decode(run.snapshotJson); var p = snapshot.profile();
        var source = sourceIndex(run);
        Map<String, NavigableSet<Integer>> changed = new HashMap<>();
        if (run.diffIndexKey != null) {
            for (var file : decode(store.get(run.diffIndexKey).orElseThrow(() -> new IOException("Diff index unavailable")), ChangedFile[].class))
                changed.put(file.file(), new TreeSet<>(file.lines()));
        }
        Set<String> ids = new LinkedHashSet<>(), tokens = new HashSet<>(); List<String> omissions = new ArrayList<>();
        int pages = 0; String token = null;
        do {
            ownership.run(); var page = gateway.list(p, run.jobId, token); pages++;
            for (var finding : page.findingsSummaries()) {
                if (finding.findingId() == null) { omissions.add("Summary without finding id"); continue; }
                ids.add(finding.findingId());
            }
            token = page.nextToken();
            if (ids.size() > MAX_FINDINGS) { omissions.add("Import bounded at 100000 returned identifiers; additional scope uncounted"); break; }
            AwsSecurityClientGateway.checkToken(token, tokens);
        } while (token != null && !token.isBlank());
        List<String> all = ids.stream().limit(MAX_FINDINGS).toList(), missing = new ArrayList<>(), shards = new ArrayList<>();
        List<Occurrence> buffer = new ArrayList<>(); int imported = 0;
        Map<String, Integer> severities = new TreeMap<>(), validations = new TreeMap<>();
        String generation = "reports/aws-security/" + run.id + "/" + UUID.randomUUID();
        Set<String> suppressedFiles = new TreeSet<>(); int omitted = 0;
        try (var sorter = new AwsSecurityFindingSort()) {
        for (int i = 0; i < all.size(); i += 10) {
            List<String> requested = all.subList(i, Math.min(i + 10, all.size()));
            Map<String, software.amazon.awssdk.services.securityagent.model.Finding> found = new LinkedHashMap<>();
            for (int attempt = 0; attempt < 3 && found.size() < requested.size(); attempt++) {
                ownership.run(); var response = gateway.details(p, requested.stream().filter(id -> !found.containsKey(id)).toList());
                for (var f : response.findings()) {
                    if (!requested.contains(f.findingId()) || !p.spaceId().equals(f.agentSpaceId())
                            || !run.jobId.equals(f.codeReviewJobId()) || !run.reviewId.equals(f.codeReviewId())) {
                        omissions.add("Unrequested or wrong-job detail rejected"); continue;
                    }
                    found.putIfAbsent(f.findingId(), f);
                }
            }
            for (String id : requested) {
                var f = found.get(id);
                if (f == null) { missing.add(id); continue; }
                var details = mapper.map(f, snapshot, run.reviewId, run.jobId, source);
                if (!details.omissions().isEmpty()) omitted++;
                if (AwsSecurityEvidencePolicy.secretFinding(f.riskType(), f.name()))
                    details.locations().forEach(l -> suppressedFiles.add(l.file()));
                severities.merge(details.severity(), 1, Integer::sum);
                var validation = software.amazon.awssdk.services.securityagent.model.ValidationStatus.fromValue(details.validationStatus());
                validations.merge(validation == null || validation == software.amazon.awssdk.services.securityagent.model.ValidationStatus.UNKNOWN_TO_SDK_VERSION ? "UNKNOWN" : validation.toString(), 1, Integer::sum);
                // Stable within one immutable run; retries cannot repoint published feedback.
                String key = RuleRevision.definition("aws-finding-occurrence", "v1").field("run", run.id).field("finding", id).hash();
                List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location> anchors = new ArrayList<>();
                for (var location : details.locations()) {
                    var lines = changed.get(location.file()); Integer anchor = lines == null ? null : lines.ceiling(location.startLine());
                    if (anchor != null && anchor <= location.endLine()) anchors.add(new com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location(location.file(), anchor, anchor, "Changed line"));
                }
                sorter.add(new Occurrence(key, details, List.copyOf(anchors))); imported++;
            }
        }
        sorter.drain(occurrence -> {
            buffer.add(occurrence);
            if (buffer.size() == PAGE_SIZE) { shards.add(writePage(generation, shards.size(), buffer, ownership)); buffer.clear(); }
        }, ownership);
        if (!buffer.isEmpty()) shards.add(writePage(generation, shards.size(), buffer, ownership));
        } catch (AwsSecurityFindingSort.LimitExceeded limit) { throw new ImportLimitExceeded(ids.size(), limit.bound); }
        if (!missing.isEmpty()) omissions.add("Returned findings have unavailable full details; retry import before publication if appropriate");
        if (!"COMPLETED".equals(run.providerStatus)) omissions.add("Provider did not complete its assessment; returned evidence is partial");
        var manifest = new AwsSecurityArtifact(2, run.id, snapshot, run.providerStatus,
            missing.isEmpty() && omissions.isEmpty() ? "COMPLETE" : "PARTIAL", pages, ids.size(), imported,
            List.copyOf(missing), List.copyOf(omissions), "pull_request".equals(run.parentType) ? 30 : null, List.copyOf(shards),
            new AwsSecurityArtifact.InputReceipt(run.sourceSha, run.sourceBytes, run.sourceFiles, run.diffSha, run.diffBytes,
                java.util.stream.Stream.concat(AwsSecurityInputStore.EXCLUDED.stream(), java.util.stream.Stream.of(".env.*", "*.pem", "*.key", "*.p12", "*.class", "*.jar", "*.zip", "*.png", "*.jpg")).sorted().toList(), "NOT_ESTABLISHED"),
            Map.copyOf(severities), Map.copyOf(validations), Set.copyOf(suppressedFiles), omitted, AwsSecurityJobReceipt.decode(run.jobReceiptJson));
        if (JSON.writeValueAsBytes(manifest).length > MAX_PAGE_BYTES) throw new ImportLimitExceeded(ids.size(), "MANIFEST_BYTES");
        String key = generation + "/manifest.json.gz"; ownership.run(); store.put(key, encode(manifest), "application/gzip");
        return new Imported(key, manifest);
    }
    private String writePage(String generation, int page, List<Occurrence> records, Runnable ownership) throws IOException {
        byte[] json = JSON.writeValueAsBytes(records);
        if (json.length > MAX_PAGE_BYTES) throw new AwsSecurityFindingSort.LimitExceeded("PAGE_BYTES");
        String key = generation + "/" + page + ".json.gz"; ownership.run(); store.put(key, encode(records), "application/gzip"); return key;
    }
    static byte[] encode(Object value) throws IOException {
        var output = new ByteArrayOutputStream();
        try (var zip = new GZIPOutputStream(output)) { JSON.writeValue(zip, value); } return output.toByteArray();
    }
    static <T> T decode(byte[] bytes, Class<T> type) throws IOException {
        if (bytes.length > MAX_PAGE_BYTES) throw new IOException("Compressed AWS artifact exceeds bound");
        try (var zip = new GZIPInputStream(new ByteArrayInputStream(bytes))) {
            byte[] data = zip.readNBytes(MAX_PAGE_BYTES + 1);
            if (data.length > MAX_PAGE_BYTES) throw new IOException("Expanded AWS artifact exceeds bound");
            return JSON.readValue(data, type);
        }
    }
    public AwsSecurityArtifact manifest(String key) throws IOException { return decode(store.get(key).orElseThrow(() -> new IOException("AWS report unavailable")), AwsSecurityArtifact.class); }
    public List<Occurrence> page(AwsSecurityArtifact manifest, int page) throws IOException {
        if (page < 0 || page >= manifest.pages().size()) throw new IllegalArgumentException("Invalid report page");
        String key = manifest.pages().get(page);
        if (!key.startsWith("reports/aws-security/" + manifest.runId() + "/")) throw new IOException("Invalid report linkage");
        return List.of(decode(store.get(key).orElseThrow(() -> new IOException("AWS finding page unavailable")), Occurrence[].class));
    }
}
