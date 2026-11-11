package com.tracelink.appsec.module.awssecurity;

import java.io.*;
import java.util.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.HtmlUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails;
import com.tracelink.appsec.watchtower.core.scan.presentation.ProviderFindingTitles;

/** All retrieval is bound to a Watchtower parent; browser-supplied AWS ids confer no authority. */
@Controller
@PreAuthorize("hasAuthority('Scan Results View')")
public class AwsSecurityReportController {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(AwsSecurityReportController.class);
    private final AwsSecurityRunRepository runs;
    private final AwsSecurityImporter importer;
    private final AwsSecurityAssessmentService assessments;
    @org.springframework.beans.factory.annotation.Autowired(required = false) private AwsSecurityClientGateway gateway;
    @org.springframework.beans.factory.annotation.Autowired(required = false) private AwsSecurityEvidencePolicy evidencePolicy;
    @org.springframework.beans.factory.annotation.Autowired private com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService integrations;
    @org.springframework.beans.factory.annotation.Autowired private com.tracelink.appsec.watchtower.core.scan.code.report.ScanReportReader localReports;
    public AwsSecurityReportController(AwsSecurityRunRepository runs, AwsSecurityImporter importer, AwsSecurityAssessmentService assessments) {
        this.runs=runs; this.importer=importer; this.assessments=assessments;
    }
    static String type(HttpServletRequest request) { return request.getRequestURI().startsWith(request.getContextPath() + "/reposcan/") ? "repository" : "pull_request"; }
    public record Excerpt(String file, String commit, int startLine, int flaggedStartLine, int requestedEndLine, List<String> lines, boolean truncated,
            List<Integer> maskedLines, boolean secretsScanned) {
        public Excerpt { maskedLines = maskedLines == null ? List.of() : List.copyOf(maskedLines); }
    }
    public record PresentedFinding(ProviderFindingDetails evidence, String title, String description, String reasoning, boolean live) { }
    public record FindingHeadline(String title, String file, Integer line) { }
    private record Located(AwsSecurityRun run, AwsSecurityArtifact manifest, ProviderFindingDetails details) { }

    private Located locate(long scanId, String key, int page, HttpServletRequest request) throws IOException {
        if (!key.matches("[a-f0-9]{64}") || page < 0 || page > 999) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        for (var run : runs.findByParentTypeAndParentIdOrderByCreatedAtAsc(type(request), scanId)) {
            if (run.artifactKey == null) continue;
            var manifest = importer.manifest(run.artifactKey);
            if (!run.id.equals(manifest.runId()) || page >= manifest.pages().size()) continue;
            for (var occurrence : importer.page(manifest, page))
                if (key.equals(occurrence.key()) && Objects.equals(run.jobId, occurrence.details().jobId())
                        && Objects.equals(run.reviewId, occurrence.details().reviewId()))
                    return new Located(run, manifest, occurrence.details());
        }
        throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
    private Optional<software.amazon.awssdk.services.securityagent.model.Finding> live(AwsSecurityRun run, ProviderFindingDetails retained) {
        if (gateway == null || run.reviewId == null || run.jobId == null) return Optional.empty();
        try {
            var profile = AwsSecuritySnapshot.decode(run.snapshotJson).profile();
            return gateway.details(profile, List.of(retained.findingId())).findings().stream()
                .filter(f -> retained.findingId().equals(f.findingId()) && profile.spaceId().equals(f.agentSpaceId())
                    && run.reviewId.equals(f.codeReviewId()) && run.jobId.equals(f.codeReviewJobId())).findFirst();
        } catch (RuntimeException unavailable) { return Optional.empty(); }
    }
    AwsSecuritySourceIndex currentSource(AwsSecuritySourceIndex index, ProviderFindingDetails retained) {
        if (index == null || evidencePolicy == null) return index;
        var allowed = new HashSet<>(evidencePolicy.sourceRiskTypes());
        // v2 and v3 receipts could freeze an empty allowlist because the application supplied
        // an empty default. Their source still requires today's reviewed policy and fresh proof.
        boolean legacyEmpty = index.approvedRiskTypes().isEmpty() && Set.of(
            "2-source-free-qualified", "3-source-free-aws-paths").contains(retained.mapperVersion());
        // A scan taken while source was on follows today's switch; one taken while it was off stays off.
        if (!legacyEmpty && index.approvedRiskTypes().isEmpty()) allowed.clear();
        return new AwsSecuritySourceIndex(index.commit(), index.archiveSha256(), index.files(), allowed, index.webAppUrl());
    }
    private AwsSecuritySourceIndex sourceIndexOrNull(AwsSecurityRun run) {
        try { return importer.sourceIndex(run); }
        catch (IOException unavailable) { return null; }
    }
    private static String bounded(String text, int limit) {
        if (text == null || text.isBlank()) return null;
        return text.length() > limit ? text.substring(0, limit) + "\n[Provider text truncated]" : text;
    }
    private static boolean sensitiveNarrative(software.amazon.awssdk.services.securityagent.model.Finding finding) {
        return AwsSecurityEvidencePolicy.secretType(finding.riskType())
            || AwsSecurityEvidencePolicy.secretType(finding.name());
    }
    private static String title(software.amazon.awssdk.services.securityagent.model.Finding finding, ProviderFindingDetails retained) {
        // A sensitive finding's own name is never shown; its risk type reads in plain words.
        String plain = ProviderFindingTitles.plain(sensitiveNarrative(finding) ? null
            : Objects.requireNonNullElse(bounded(finding.name(), 512), retained.title()), retained.riskType());
        return plain;
    }
    @GetMapping({"/scan/report/{scanId}/aws/findings/{key}/source", "/reposcan/report/{scanId}/aws/findings/{key}/source"}) @ResponseBody
    public Excerpt source(@PathVariable long scanId, @PathVariable String key, @RequestParam(defaultValue="0") int page,
            @RequestParam int location, HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store"); response.setHeader("X-Content-Type-Options", "nosniff");
        if (location < 0) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        var located = locate(scanId, key, page, request);
        var run = located.run(); var manifest = located.manifest();
        var snapshot = AwsSecuritySnapshot.decode(run.snapshotJson); var context = snapshot.context();
        AwsSecuritySourceIndex savedIndex;
        try { savedIndex = importer.sourceIndex(run); }
        catch (IOException unavailable) { throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Source proof unavailable"); }
        var index = currentSource(savedIndex, located.details());
        var original = live(run, located.details());
        if (original.isEmpty() && "2-source-free-qualified".equals(located.details().mapperVersion()))
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "AWS finding unavailable");
        var finding = original.map(f -> new AwsSecurityFindingMapper().map(f, snapshot, run.reviewId, run.jobId, index))
            .orElse(located.details());
        if (finding.sensitive()) throw refused(scanId, "the finding is classed as sensitive");
        if (!finding.sourceLocations().contains(location) || location >= finding.locations().size())
            throw refused(scanId, "location " + location + " is not one whose code may be shown");
        var range = finding.locations().get(location);
                if (index == null) throw refused(scanId, "no source proof was saved with the scan");
                if (!index.permits(finding.riskType())) throw refused(scanId, "source is not allowed for risk type " + finding.riskType());
                if (manifest.sourceSuppressedFiles().contains(range.file())) throw refused(scanId, "the file has a secret-like finding");
                if (!localReports.permitsSource(type(request), scanId, context.commit(), range.file()))
                    throw refused(scanId, "the local report is not complete at commit " + context.commit());
                var file = index.file(range.file()).orElseThrow(() -> refused(scanId, "the file is not in the uploaded source"));
                if (!ProviderFindingDetails.Location.valid(file.path(), range.startLine(), range.endLine()) || file.bytes() < 1 || file.bytes() > AwsSecurityInputStore.MAX_FILE)
                    throw refused(scanId, "the file or its line range is not valid or is too large");
                var integration = integrations.findByLabel(context.apiLabel());
                if (integration == null || !(integration.createApi() instanceof com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi api)) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
                byte[] bytes;
                try {
                    bytes = api.boundedFileAtCommit(context.repository(), context.commit(), file.path(),
                        (int)Math.min(AwsSecurityInputStore.MAX_FILE, file.bytes() + 1));
                } catch (IOException unavailable) {
                    LOG.warn("Pinned source fetch failed for scan {}", scanId, unavailable);
                    throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                        "Scanned source is temporarily unavailable from the code host", unavailable);
                }
                if (bytes == null || bytes.length != file.bytes() || !file.sha256().equals(AwsSecurityInputStore.sha256(bytes))) throw new ResponseStatusException(HttpStatus.CONFLICT, "Pinned source proof mismatch");
                int displayStart = Math.max(1, range.startLine() - 3);
                int displayEnd = (int) Math.min((long) range.endLine() + 3, (long) displayStart + 79);
                // Lines a local secrets scanner flagged are masked, as in the pull request Code section.
                var secrets = localReports.secretLines(type(request), scanId, range.file());
                List<String> lines = new ArrayList<>(); List<Integer> masked = new ArrayList<>(); int line = 0;
                var decoder = java.nio.charset.StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT);
                try (var reader = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(bytes), decoder))) {
                    String text;
                    while ((text = reader.readLine()) != null) {
                        line++;
                        if (line >= displayStart && secrets.contains(line)) {
                            lines.add(com.tracelink.appsec.watchtower.core.scan.code.report.CodeExcerpts.MASKED_LINE_TEXT); masked.add(line);
                        } else if (line >= displayStart) {
                            if (text.length() > 8192 || text.indexOf('\0') >= 0) throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "Source line exceeds display bound");
                            lines.add(text);
                        }
                        if (line >= displayEnd || lines.size() == 80) break;
                    }
                }
                if (lines.isEmpty() || lines.size() < 80 && line < range.endLine()) throw new ResponseStatusException(HttpStatus.CONFLICT, "Source range unavailable");
                return new Excerpt(file.path(), context.commit(), displayStart, range.startLine(), range.endLine(), List.copyOf(lines), line < range.endLine(), masked,
                    localReports.secretsScannerRan(type(request), scanId));
    }
    /** A refused source request: the reason is logged for the operator; the browser only sees the status. */
    private static ResponseStatusException refused(long scanId, String reason) {
        LOG.info("AWS source not shown for scan {}: {}", scanId, reason);
        return new ResponseStatusException(HttpStatus.FORBIDDEN);
    }
    static final String HIDDEN_FILE_REASON = "Code in this file is hidden because AWS reported a secret or credential finding in it.";
    /** A file with a secret-like finding is hidden for every finding in it; the chip says so instead of failing when it is opened. */
    static ProviderFindingDetails hideSuppressedFiles(ProviderFindingDetails details, Set<String> hiddenFiles) {
        if (hiddenFiles.isEmpty() || details.sourceLocations().isEmpty()) return details;
        var shown = details.sourceLocations().stream()
            .filter(i -> i < details.locations().size() && !hiddenFiles.contains(details.locations().get(i).file())).toList();
        return shown.size() == details.sourceLocations().size() ? details : details.withSourceLocations(shown, HIDDEN_FILE_REASON);
    }
    @GetMapping({"/scan/report/{scanId}/aws/status", "/reposcan/report/{scanId}/aws/status"}) @ResponseBody
    public Object status(@PathVariable long scanId, HttpServletRequest request) { return assessments.status(type(request), scanId); }
    @GetMapping({"/scan/report/{scanId}/aws/findings/{key}", "/reposcan/report/{scanId}/aws/findings/{key}"}) @ResponseBody
    public PresentedFinding detail(@PathVariable long scanId, @PathVariable String key,
            @RequestParam(defaultValue = "0") int page, HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store"); response.setHeader("X-Content-Type-Options", "nosniff");
        var found = locate(scanId, key, page, request);
        var original = live(found.run(), found.details());
        var hiddenFiles = found.manifest().sourceSuppressedFiles();
        if (original.isEmpty()) return new PresentedFinding(hideSuppressedFiles(found.details(), hiddenFiles), ProviderFindingTitles.plain(found.details().title(), found.details().riskType()), null, null, false);
        var run = found.run();
        var mapped = new AwsSecurityFindingMapper().map(original.get(), AwsSecuritySnapshot.decode(run.snapshotJson),
            run.reviewId, run.jobId, currentSource(sourceIndexOrNull(run), found.details()));
        boolean sensitive = sensitiveNarrative(original.get());
        return new PresentedFinding(hideSuppressedFiles(mapped, hiddenFiles), title(original.get(), found.details()),
            sensitive ? null : bounded(original.get().description(), 32768),
            sensitive ? null : bounded(original.get().reasoning(), 16384), true);
    }

    @GetMapping({"/scan/report/{scanId}/aws/titles", "/reposcan/report/{scanId}/aws/titles"}) @ResponseBody
    public Map<String, FindingHeadline> titles(@PathVariable long scanId, @RequestParam(defaultValue = "0") int page,
            HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store"); response.setHeader("X-Content-Type-Options", "nosniff");
        if (page < 0 || page > 999) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        var titles = new LinkedHashMap<String, FindingHeadline>();
        if (gateway == null) return titles;
        for (var run : runs.findByParentTypeAndParentIdOrderByCreatedAtAsc(type(request), scanId)) {
            if (run.artifactKey == null) continue;
            var manifest = importer.manifest(run.artifactKey);
            if (!run.id.equals(manifest.runId()) || page >= manifest.pages().size()) continue;
            var occurrences = importer.page(manifest, page);
            var profile = AwsSecuritySnapshot.decode(run.snapshotJson).profile();
            var source = sourceIndexOrNull(run);
            for (int i = 0; i < occurrences.size(); i += 10) {
                var batch = occurrences.subList(i, Math.min(i + 10, occurrences.size()));
                try {
                    var original = gateway.details(profile, batch.stream().map(o -> o.details().findingId()).toList());
                    for (var finding : original.findings()) for (var occurrence : batch) {
                        var saved = occurrence.details();
                        if (saved.findingId().equals(finding.findingId()) && profile.spaceId().equals(finding.agentSpaceId())
                                && run.reviewId.equals(finding.codeReviewId()) && run.jobId.equals(finding.codeReviewJobId())) {
                            var mapped = new AwsSecurityFindingMapper().map(finding, AwsSecuritySnapshot.decode(run.snapshotJson),
                                run.reviewId, run.jobId, currentSource(source, saved));
                            var first = mapped.locations().isEmpty() ? null : mapped.locations().getFirst();
                            titles.put(occurrence.key(), new FindingHeadline(title(finding, saved),
                                first == null ? null : first.file(), first == null ? null : first.startLine()));
                        }
                    }
                } catch (RuntimeException unavailable) { /* Retained finding list still loads. */ }
            }
        }
        return titles;
    }
    @GetMapping({"/scan/report/{scanId}/aws/export", "/reposcan/report/{scanId}/aws/export"})
    public void export(@PathVariable long scanId, @RequestParam(defaultValue = "json") String format,
            HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!Set.of("json", "sarif", "csv", "html").contains(format)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        var rows = runs.findByParentTypeAndParentIdOrderByCreatedAtAsc(type(request), scanId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'");
        response.setContentType(switch (format) { case "csv" -> "text/csv;charset=UTF-8"; case "html" -> "text/html;charset=UTF-8"; default -> "application/json;charset=UTF-8"; });
        if (!format.equals("html")) response.setHeader("Content-Disposition", "attachment; filename=aws-assessment-" + scanId + "." + format);
        var out = response.getWriter();
        if (format.equals("csv")) out.println("record_type,assessment_state,import_status,commit,finding_key,finding_id,native_severity,confidence,validation,risk_type,title,file,start_line,end_line,additional_locations,omissions");
        if (format.equals("html")) out.println("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>AWS assessment</title><style>body{font:16px system-ui;max-width:960px;margin:3rem auto}article{break-inside:avoid;border-top:1px solid #ccc;padding:1rem 0}code{overflow-wrap:anywhere}</style><h1>AWS Security Agent assessment</h1><p>Source-free retained evidence. Confidence is not reproduced exploitation. Cross-run remediation is not established.</p>");
        if (format.equals("json")) out.print("{\"schema\":1,\"assessments\":[");
        if (format.equals("sarif")) out.print("{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"runs\":[");
        boolean firstRun = true;
        for (var row : rows) {
            var manifest = row.artifactKey == null ? null : importer.manifest(row.artifactKey);
            String importStatus = manifest == null ? "UNAVAILABLE" : manifest.importStatus();
            var snapshot = AwsSecuritySnapshot.decode(row.snapshotJson);
            Map<String, Object> receipt = new LinkedHashMap<>();
            receipt.put("state", row.stage.name()); receipt.put("reason", row.statusReason); receipt.put("importStatus", importStatus);
            receipt.put("snapshot", snapshot); receipt.put("manifest", manifest); receipt.put("createdAt", row.createdAt); receipt.put("terminalAt", row.terminalAt);
            receipt.put("cleanupComplete", row.cleanupComplete); receipt.put("imported", row.importedCount); receipt.put("missing", row.missingCount);
            if (format.equals("json") || format.equals("sarif")) {
                if (!firstRun) out.print(','); firstRun = false;
                if (format.equals("json")) { out.print("{\"receipt\":" + JSON.writeValueAsString(receipt) + ",\"findings\":["); }
                else out.print("{\"tool\":{\"driver\":{\"name\":\"AWS Security Agent\",\"version\":\"unknown\"}},\"properties\":"
                    + JSON.writeValueAsString(receipt) + ",\"results\":[");
            }
            if (format.equals("csv")) out.println(csv("assessment", row.stage, importStatus, snapshot.context().commit(), "", "", "", "", "", "", "", "", "", "", "",
                "Imported=" + row.importedCount + "; missing=" + row.missingCount + "; providerCap=" + ("pull_request".equals(row.parentType) ? "30" : "UNKNOWN") + "; " + Objects.toString(row.statusReason, "") + "; source-free evidence; comparison NOT_ESTABLISHED"));
            if (format.equals("html")) out.println("<h2>" + html(row.stage.name()) + "</h2><p>Commit <code>" + html(snapshot.context().commit()) + "</code> · Import " + html(importStatus) + "</p><p>" + html(row.statusReason) + "</p><p>" + ("pull_request".equals(row.parentType) ? "AWS differential reviews return at most 30 prioritized findings." : "Provider coverage is not exhaustive detection.") + "</p>");
            boolean firstFinding = true;
            if (manifest != null) for (int page = 0; page < manifest.pages().size(); page++) for (var occurrence : importer.page(manifest, page)) {
                var f = occurrence.details(); var location = f.locations().isEmpty() ? null : f.locations().getFirst();
                if (format.equals("json") || format.equals("sarif")) {
                    if (!firstFinding) out.print(','); firstFinding = false;
                    out.print(JSON.writeValueAsString(format.equals("json") ? occurrence : sarif(occurrence)));
                } else if (format.equals("csv")) {
                    out.println(csv("finding", row.stage, importStatus, snapshot.context().commit(), occurrence.key(), f.findingId(), f.nativeSeverity(), f.confidence(),
                        f.validationStatus(), f.riskType(), f.title(), location == null ? null : location.file(), location == null ? null : location.startLine(),
                        location == null ? null : location.endLine(), JSON.writeValueAsString(f.locations()), String.join("; ", f.omissions())));
                } else {
                    out.println("<article><h3>" + html(f.title()) + "</h3><p>" + html(f.nativeSeverity()) + " · Confidence " + html(f.confidence()) + " · Validation " + html(f.validationStatus()) + "</p><p>Finding <code>" + html(f.findingId()) + "</code></p>");
                    for (var l : f.locations()) out.println("<p><code>" + html(l.file()) + ":" + l.startLine() + "–" + l.endLine() + "</code></p>");
                    for (var omission : f.omissions()) out.println("<p>" + html(omission) + "</p>"); out.println("</article>");
                }
            }
            if (manifest != null && format.equals("html")) { for (var omission : manifest.omissions()) out.println("<p>" + html(omission) + "</p>"); out.println("<p>Missing detail records: " + manifest.missingIds().size() + "</p>"); }
            if (format.equals("html")) out.println("<details open><summary>Assessment receipt</summary><pre style=\"white-space:pre-wrap;overflow-wrap:anywhere\">" + html(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(receipt)) + "</pre></details>");
            if (format.equals("json") || format.equals("sarif")) out.print("]}");
        }
        if (format.equals("json") || format.equals("sarif")) out.print("]}");
        if (format.equals("html")) out.print("</html>");
    }
    static Map<String,Object> sarif(AwsSecurityArtifact.Occurrence occurrence) {
        var f = occurrence.details(); Map<String,Object> result = new LinkedHashMap<>();
        result.put("ruleId", "aws-security-review/" + Objects.toString(f.riskType(), "unknown"));
        result.put("level", switch (f.severity()) { case "CRITICAL", "HIGH" -> "error"; case "MEDIUM", "LOW" -> "warning"; default -> "note"; });
        result.put("message", Map.of("text", f.title())); result.put("partialFingerprints", Map.of("watchtowerOccurrence/v1", occurrence.key()));
        result.put("locations", f.locations().stream().map(l -> Map.of("physicalLocation", Map.of("artifactLocation", Map.of("uri", uri(l.file())),
            "region", Map.of("startLine", l.startLine(), "endLine", l.endLine())))).toList());
        result.put("properties", f); return result;
    }
    private static String uri(String path) { try { return new java.net.URI(null, null, path, null).toASCIIString(); } catch (Exception e) { throw new IllegalArgumentException("Invalid finding path"); } }
    static String csv(Object... cells) { return Arrays.stream(cells).map(v -> {
        String s = Objects.toString(v, ""); String leading = s.stripLeading();
        if (!s.isEmpty() && ("\t\r\n".indexOf(s.charAt(0)) >= 0 || !leading.isEmpty() && "=+-@".indexOf(leading.charAt(0)) >= 0)) s = "'" + s;
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }).collect(java.util.stream.Collectors.joining(",")); }
    private static String html(String value) { return HtmlUtils.htmlEscape(Objects.toString(value, "Not provided")); }
}
