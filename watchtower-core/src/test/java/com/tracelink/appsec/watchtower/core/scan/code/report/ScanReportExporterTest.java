package com.tracelink.appsec.watchtower.core.scan.code.report;

import java.util.*;
import java.io.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.*;

class ScanReportExporterTest {
    static final class AuthorizationDialect extends org.thymeleaf.dialect.AbstractDialect implements org.thymeleaf.dialect.IExpressionObjectDialect {
        AuthorizationDialect() { super("fixture-authorization"); }
        public org.thymeleaf.expression.IExpressionObjectFactory getExpressionObjectFactory() {
            return new org.thymeleaf.expression.IExpressionObjectFactory() {
                public Set<String> getAllExpressionObjectNames() { return Set.of("authorization"); }
                public Object buildObject(org.thymeleaf.context.IExpressionContext context, String name) { return new FixtureAuthorization(); }
                public boolean isCacheable(String name) { return true; }
            };
        }
    }
    public static final class FixtureAuthorization { public boolean expression(String ignored) { return false; } }
    private final ObjectMapper json = new ObjectMapper();
    private ProviderAssessmentReference reference(int count, int pages) {
        var status = new RemoteAssessmentService.Status("run", "PARTIAL", "Missing detail", "a".repeat(40), null, "review", "job", count, 1, false, false, 30, pages, Map.of("CRITICAL", count));
        var context = new ScanExecutionContext("execution", CodeScanType.REPOSITORY, 1, 2, "bb", "repo", "main", "a".repeat(40), null, null, null, null);
        return new ProviderAssessmentReference("AWS_SECURITY_AGENT", "run", "manifest", status, context, null, "AWS policy", "revision", Map.of("UNKNOWN", count), count);
    }
    private RemoteAssessmentService.ProviderOccurrence finding(String key) {
        var details = new ProviderFindingDetails("AWS_SECURITY_AGENT", "account", "region", "space", "review", "job", key, null, "mapper", "<script>title</script>", null, "SQL_INJECTION", "CRITICAL", "9.8", null, "HIGH", "NOT_VALIDATED", "OPEN", List.of(new ProviderFindingDetails.Location("src/one.java", 1, 3, null), new ProviderFindingDetails.Location("src/two.java", 8, 9, null)), List.of("Source-free omission"), true);
        return new RemoteAssessmentService.ProviderOccurrence(key, details, List.of());
    }
    @Test void allFormatsCombineLocalAndEveryProviderPageWithoutInventingCleanOrFixed() throws Exception {
        var reader = mock(ScanReportReader.class); var remote = mock(RemoteAssessmentService.class); var exporter = new ScanReportExporter(reader);
        ReflectionTestUtils.setField(exporter, "remote", remote); var reference = reference(2, 2);
        var local = new RepoScanReport(4, 1, "bb", "repo", "main", "a".repeat(40), "rules", List.of(new RepoScanReport.Finding("Local rule", "High", "src/local.java", 5, "local evidence", "fp", false, false)), List.of(), List.of(), 1, null, null, List.of(reference));
        when(reader.read("repository", 1)).thenReturn(local); when(remote.reports("repository", 1)).thenReturn(List.of(reference));
        when(remote.receipt(reference)).thenReturn(reference); when(remote.evidence(reference, 0)).thenReturn(List.of(finding("one"))); when(remote.evidence(reference, 1)).thenReturn(List.of(finding("two")));
        for (String format : List.of("json", "sarif", "csv", "html")) {
            var response = new MockHttpServletResponse(); exporter.export("repository", 1, format, response); String body = response.getContentAsString();
            assertTrue(body.contains("local evidence")); assertTrue(body.contains("src/two.java")); assertTrue(body.contains("NOT_VALIDATED")); assertTrue(body.contains("PARTIAL")); assertEquals("no-store", response.getHeader("Cache-Control")); assertEquals("UTF-8", response.getCharacterEncoding(), format);
            if (format.equals("json")) { var root = json.readTree(body); assertEquals(1, root.path("local").path("findings").size()); assertEquals(2, root.path("assessments").get(0).path("findings").size()); assertTrue(root.path("assessments").get(0).path("exportComplete").asBoolean()); }
            if (format.equals("sarif")) { var runs = json.readTree(body).path("runs"); assertEquals(2, runs.size()); assertEquals("Watchtower", runs.get(0).path("tool").path("driver").path("name").asText()); assertEquals(2, runs.get(1).path("results").size()); assertFalse(runs.get(1).path("invocations").get(0).path("executionSuccessful").asBoolean()); }
            if (format.equals("html")) { assertFalse(body.contains("<script>")); assertTrue(body.contains("&lt;script&gt;")); }
        }
        assertEquals(3, local.combinedTotalFindings()); assertFalse(local.providerComplete()); assertEquals(0, local.fixed().size());
    }
    @Test void unavailablePageIsExplicitlyIncompleteAndKeepsAvailableEvidence() throws Exception {
        var reader = mock(ScanReportReader.class); var remote = mock(RemoteAssessmentService.class); var exporter = new ScanReportExporter(reader); ReflectionTestUtils.setField(exporter, "remote", remote);
        var reference = reference(2, 2); when(reader.read("repository", 1)).thenReturn(new RepoScanReport(4, 1, "bb", "repo", "main", "commit", "rules", List.of(), List.of(), List.of(), 0));
        when(remote.reports("repository", 1)).thenReturn(List.of(reference)); when(remote.receipt(reference)).thenReturn(reference); when(remote.evidence(reference, 0)).thenReturn(List.of(finding("one"))); when(remote.evidence(reference, 1)).thenThrow(new IOException("source-bearing transport error must not be printed"));
        for (String format : List.of("json", "sarif", "csv", "html")) {
            var response = new MockHttpServletResponse(); exporter.export("repository", 1, format, response); String body = response.getContentAsString();
            assertTrue(body.contains("INCOMPLETE_EXPORT")); assertFalse(body.contains("source-bearing"));
            if (format.equals("json")) assertFalse(json.readTree(body).path("assessments").get(0).path("exportComplete").asBoolean());
        }
    }
    @Test void schemaFourAndLegacyReportsRoundTripWithUnchangedLocalCounts() throws Exception {
        var legacy = new RepoScanReport(3, 1, "bb", "repo", "main", "commit", "rules", List.of(), List.of(), List.of(), 0);
        assertTrue(RepoReportCodec.decode(RepoReportCodec.encode(legacy)).providerAssessments().isEmpty());
        var ref = reference(4, 1);
        assertEquals(List.of(ref), ProviderAssessmentReference.decode(ProviderAssessmentReference.encode(List.of(ref))));
        var report = new RepoScanReport(4, 1, "bb", "repo", "main", "commit", "rules", List.of(), List.of(), List.of(), 0, null, null, List.of(ref));
        var decoded = RepoReportCodec.decode(RepoReportCodec.encode(report)); assertEquals(0, decoded.totalFindings()); assertEquals(4, decoded.combinedTotalFindings()); assertEquals(List.of(ref), decoded.providerAssessments());
        assertEquals("0,0,0,0,0,0", com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts.of(List.of()).format());
        assertTrue(RepoScanExporter.cell("  =HYPERLINK(x)").startsWith("\"'"));
    }
    @Test void realSharedWorkspaceRendersCriticalUnknownAndIncompleteStates() throws Exception {
        var resolver = new org.thymeleaf.templateresolver.ClassLoaderTemplateResolver(); resolver.setPrefix("templates/"); resolver.setSuffix(".html"); resolver.setTemplateMode("HTML");
        var engine = new org.thymeleaf.spring6.SpringTemplateEngine(); engine.setTemplateResolver(resolver); engine.addDialect(new AuthorizationDialect());
        var servlet = new org.springframework.mock.web.MockServletContext(); var request = new org.springframework.mock.web.MockHttpServletRequest(servlet); var response = new MockHttpServletResponse();
        var application = org.thymeleaf.web.servlet.JakartaServletWebApplication.buildApplication(servlet);
        var context = new org.thymeleaf.context.WebContext(application.buildExchange(request, response));
        var detail = finding("a".repeat(64)).details();
        var first = com.tracelink.appsec.watchtower.core.scan.presentation.FindingPresentationModel.fromProvider("a".repeat(64), detail).withProviderDetailUrl("/scan/report/1/aws/findings/" + "a".repeat(64) + "?page=0");
        assertEquals("Open in AWS", first.getExternalUrlLabel());
        var unknown = new ProviderFindingDetails(detail.provider(), detail.account(), detail.region(), detail.spaceId(), detail.reviewId(), detail.jobId(), "other", null, "mapper", "Unknown finding", null, null, "FUTURE", null, null, "HIGH", "NOT_VALIDATED", "OPEN", detail.locations(), detail.omissions(), true);
        var second = com.tracelink.appsec.watchtower.core.scan.presentation.FindingPresentationModel.fromProvider("b".repeat(64), unknown).withProviderDetailUrl("/scan/report/1/aws/findings/" + "b".repeat(64) + "?page=0");
        context.setVariable("heading", "Security findings"); context.setVariable("findings", List.of(first, second)); context.setVariable("scanFailed", true); context.setVariable("sourceViewerAvailable", true);
        String html = engine.process("fragments/findings", Set.of("workspace"), context);
        assertTrue(html.contains("data-severity=\"CRITICAL\"")); assertTrue(html.contains("data-severity=\"UNKNOWN\"")); assertTrue(html.contains("data-provider-detail-url=")); assertFalse(html.contains("<script>title</script>"));
        var output = java.nio.file.Files.createTempDirectory("watchtower-aws-ui-").resolve("report.html");
        java.nio.file.Files.writeString(output, "<!doctype html><html><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>AWS report fixture</title></head><body>" + html + "</body></html>");
        System.out.println("AWS_UI_FIXTURE=" + output);
        context.setVariable("findings", List.of());
        String empty = engine.process("fragments/findings", Set.of("workspace"), context);
        assertTrue(empty.contains("No findings, but this wasn&#39;t a full scan") || empty.contains("No findings, but this wasn't a full scan")); assertFalse(empty.contains("The completed scan did not report"));
    }
}
