package com.tracelink.appsec.watchtower.core.scan.code.report;

import java.io.*;
import java.util.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.HtmlUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService;
import com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.ProviderOccurrence;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.*;

/** Shared full exports. Provider pages are streamed, preserving native evidence and partial states. */
@Service
public class ScanReportExporter {
    private static final ObjectMapper JSON = new ObjectMapper();
    @Autowired(required = false) private RemoteAssessmentService remote;
    private final ScanReportReader reader;
    public ScanReportExporter(ScanReportReader reader) { this.reader = reader; }
    public void export(String type, long id, String format, HttpServletResponse response) throws IOException {
        if (!Set.of("json", "sarif", "csv", "html").contains(format)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        RepoScanReport report = reader.read(type, id).interpreted();
        var references = remote == null ? report.providerAssessments() : remote.reports(type, id);
        // Preserve references from a stored report even if a provider module is temporarily unavailable.
        if (references.isEmpty() && !report.providerAssessments().isEmpty()) references = report.providerAssessments();
        var assessment = com.tracelink.appsec.watchtower.core.scan.presentation.ScanAssessment.from(report, references);
        response.setHeader("Cache-Control", "no-store"); response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'");
        // Findings carry non-ASCII text; without this the JSON and SARIF writers fall back to ISO-8859-1.
        response.setCharacterEncoding("UTF-8");
        response.setContentType(switch (format) { case "html" -> "text/html;charset=UTF-8"; case "csv" -> "text/csv;charset=UTF-8"; case "sarif" -> "application/sarif+json"; default -> "application/json"; });
        if (!format.equals("html")) response.setHeader("Content-Disposition", "attachment; filename=scan-" + id + "." + format);
        Writer out = response.getWriter();
        switch (format) {
            case "json" -> out.write("{\"schema\":4,\"local\":" + JSON.writeValueAsString(report) + ",\"assessments\":[");
            case "sarif" -> {
                var local = new ByteArrayOutputStream(); RepoScanExporter.sarif(report, local);
                var run = JSON.readTree(local.toByteArray()).path("runs").get(0).deepCopy();
                ((com.fasterxml.jackson.databind.node.ObjectNode) run).set("properties", JSON.valueToTree(Map.of("scannerErrors", report.scannerErrors(), "truncated", report.isTruncated(), "comparison", report.comparison(), "assessment", assessment, "commit", Objects.toString(report.commitHash(), "UNKNOWN"))));
                out.write("{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"runs\":[" + JSON.writeValueAsString(run));
            }
            case "csv" -> {
                out.write("record_type,provider,state,repository,commit,finding_key,rule,native_severity,confidence,validation,risk_type,title,file,start_line,end_line,all_locations,omissions,receipt\r\n");
                row(out, "assessment", "Watchtower", report.scannerErrors().isEmpty() ? "LOCAL_RESULTS" : "INCOMPLETE", report.repository(), report.commitHash(), "", "", "", "", "", "", "", "", "", "", "", String.join("; ", report.scannerErrors()), JSON.writeValueAsString(Map.of("comparison", report.comparison(), "assessment", assessment, "total", report.totalFindings(), "retained", report.findings().size(), "truncated", report.isTruncated())));
                for (var f : report.findings()) row(out, "finding", "Watchtower", "", report.repository(), report.commitHash(), f.findingKey(), f.rule(), f.severity(), "", "", "", f.message(), f.file(), f.line(), f.line(), "", "", "");
            }
            case "html" -> {
                out.write("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Watchtower scan report</title><style>body{font:16px system-ui;max-width:1000px;margin:3rem auto}article{break-inside:avoid;border-top:1px solid #ccc;padding:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Watchtower scan report</h1>");
                out.write("<p>" + html(report.repository()) + " · Commit " + html(report.commitHash()) + "</p><h2>Local findings</h2>");
                out.write("<h2>Assessment and comparison</h2><pre>" + html(JSON.writeValueAsString(assessment)) + "\n" + html(JSON.writeValueAsString(report.comparison())) + "</pre>");
                for (var f : report.findings()) out.write("<article><h3>" + html(f.rule()) + "</h3><pre>" + html(JSON.writeValueAsString(f)) + "</pre></article>");
                out.write("<p>Local total " + report.totalFindings() + "; retained " + report.findings().size() + "; truncated " + report.isTruncated() + "</p>");
                for (var error : report.scannerErrors()) out.write("<p>" + html(error) + "</p>");
            }
        }
        boolean first = true;
        for (var reference : references) {
            Object receipt = reference; boolean exportComplete = true;
            try { if (remote == null) throw new IOException(); receipt = remote.receipt(reference); }
            catch (IOException | RuntimeException unavailable) { exportComplete = false; }
            String metadata = JSON.writeValueAsString(receipt);
            switch (format) {
                case "json" -> { if (!first) out.write(','); out.write("{\"receipt\":" + metadata + ",\"findings\":["); }
                case "sarif" -> out.write(",{\"tool\":{\"driver\":{\"name\":\"AWS Security Agent\",\"version\":\"unknown\"}},\"properties\":" + metadata + ",\"results\":[");
                case "csv" -> row(out, "assessment", reference.provider(), reference.status().state(), report.repository(), reference.context().commit(), "", reference.policyName(), "", "", "", "", "", "", "", "", "", "", metadata);
                case "html" -> out.write("<h2>AWS Security Agent · " + html(reference.status().state()) + "</h2><p>Confidence is separate from validation. Cross-run remediation is not established.</p><pre>" + html(metadata) + "</pre>");
            }
            first = false; boolean firstFinding = true; int count = 0;
            if (exportComplete) for (int page = 0; page < reference.status().pages(); page++) {
                List<ProviderOccurrence> findings;
                try { findings = remote.evidence(reference, page); }
                catch (IOException | RuntimeException unavailable) { exportComplete = false; break; }
                for (var occurrence : findings) {
                    count++; var f = occurrence.details(); var location = f.locations().isEmpty() ? null : f.locations().getFirst();
                    if (format.equals("json") || format.equals("sarif")) {
                        if (!firstFinding) out.write(','); firstFinding = false;
                        out.write(JSON.writeValueAsString(format.equals("json") ? occurrence : sarif(occurrence)));
                    } else if (format.equals("csv")) row(out, "finding", reference.provider(), reference.status().state(), report.repository(), reference.context().commit(), occurrence.key(), reference.policyName(), f.nativeSeverity(), f.confidence(), f.validationStatus(), f.riskType(), f.title(), location == null ? "" : location.file(), location == null ? "" : location.startLine(), location == null ? "" : location.endLine(), JSON.writeValueAsString(f.locations()), String.join("; ", f.omissions()), JSON.writeValueAsString(f));
                    else out.write("<article><h3>" + html(f.title()) + "</h3>" + providerLink(f) + "<pre>" + html(JSON.writeValueAsString(occurrence)) + "</pre></article>");
                }
            }
            exportComplete &= count == reference.status().imported();
            String state = exportComplete ? "RETAINED_EVIDENCE_EXPORTED" : "INCOMPLETE_EXPORT: retained evidence unavailable";
            if (format.equals("json")) out.write("],\"exportComplete\":" + exportComplete + ",\"exportState\":" + JSON.writeValueAsString(state) + "}");
            else if (format.equals("sarif")) out.write("],\"invocations\":[{\"executionSuccessful\":" + (exportComplete && reference.status().complete()) + ",\"properties\":{\"exportComplete\":" + exportComplete + ",\"exportState\":" + JSON.writeValueAsString(state) + "}}]}");
            else if (format.equals("csv")) row(out, "export_status", reference.provider(), state, report.repository(), reference.context().commit(), "", "", "", "", "", "", "", "", "", "", "", "", "");
            else out.write("<p>" + html(state) + "</p>");
        }
        out.write(format.equals("json") || format.equals("sarif") ? "]}" : format.equals("html") ? "</html>" : ""); out.flush();
    }
    public static Map<String, Object> sarif(ProviderOccurrence occurrence) {
        var f = occurrence.details(); Map<String, Object> result = new LinkedHashMap<>();
        result.put("ruleId", "aws-security-review/" + Objects.toString(f.riskType(), "unknown"));
        result.put("level", switch (f.severity()) { case "CRITICAL", "HIGH" -> "error"; case "MEDIUM", "LOW" -> "warning"; default -> "note"; });
        result.put("message", Map.of("text", f.title())); result.put("partialFingerprints", Map.of("watchtowerOccurrence/v1", occurrence.key()));
        result.put("locations", f.locations().stream().map(l -> Map.of("physicalLocation", Map.of("artifactLocation", Map.of("uri", uri(l.file())), "region", Map.of("startLine", l.startLine(), "endLine", l.endLine())))).toList());
        result.put("properties", f); return result;
    }
    private static String uri(String path) { try { return new java.net.URI(null, null, path, null).toASCIIString(); } catch (Exception e) { throw new IllegalArgumentException("Invalid evidence path"); } }
    private static void row(Writer out, Object... cells) throws IOException {
        out.write(Arrays.stream(cells).map(c -> RepoScanExporter.cell(Objects.toString(c, ""))).collect(java.util.stream.Collectors.joining(","))); out.write("\r\n");
    }
    private static String providerLink(ProviderFindingDetails details) {
        String url = details.providerUrl(); if (url == null || !url.startsWith("https://")) return "";
        return "<p><a rel=\"noopener noreferrer\" href=\"" + html(url) + "\">Open AWS evidence (AWS authorization required)</a></p>";
    }
    private static String html(String value) { return HtmlUtils.htmlEscape(Objects.toString(value, "Not provided")); }
}
