package com.tracelink.appsec.module.awssecurity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.mock.web.*;
import org.springframework.web.server.ResponseStatusException;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.AbstractScmIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.report.ScanReportReader;
import software.amazon.awssdk.services.securityagent.model.*;

class AwsSecurityEvidenceTest {
    @TempDir Path temp;
    @Test void anAwsPathInEitherExtractionFormMapsToTheUploadedFile() {
        var index = new AwsSecuritySourceIndex("c", "sha", List.of(new AwsSecuritySourceIndex.File("src/A.java", "sha", 10)), Set.of(), "");
        String root = "code_sc-d0362a3f-65a5-489f-868c-d5efb15fe4bc/";
        assertEquals(Optional.of("src/A.java"), index.exportedPath("/tmp/opt/source_code/" + root + "src/A.java"));
        assertEquals(Optional.of("src/A.java"), index.exportedPath(root + "src/A.java"));
        assertEquals(Optional.of("src/A.java"), index.exportedPath("src/A.java"));
        assertEquals(Optional.empty(), index.exportedPath("/etc/passwd"));
        assertEquals(Optional.empty(), index.exportedPath("/tmp/opt/source_code/other/src/A.java"));
        assertEquals(Optional.empty(), index.exportedPath(root + "../src/A.java"));
        assertEquals(Optional.empty(), index.exportedPath(root + "src/Missing.java"));
    }
    @Test void onlyATitleAboutASecretMarksAFindingAsOne() {
        for (String ordinary : List.of("Insecure direct object reference exposes sensitive scan data", "Authentication bypass lets any caller read an image scan",
                "Unknown caller can read any image scan", "Business logic flaw in violation filtering"))
            assertFalse(AwsSecurityEvidencePolicy.secretFinding("BUSINESS_LOGIC_VULNERABILITIES", ordinary), ordinary);
        for (String secret : List.of("Hardcoded Slack webhook/bot-token credentials and RSA private key file", "Default password committed", "AWS access key in source", "API key in config",
                "Hardcoded Slack webhook URL and bot token committed in ImageSecurityReport", "Token stored in plain text"))
            assertTrue(AwsSecurityEvidencePolicy.secretFinding("OTHER", secret), secret);
        assertTrue(AwsSecurityEvidencePolicy.secretFinding("HARDCODED_CREDENTIALS", "Ordinary title"));
    }
    @Test void aFileHiddenBySecretFindingOffersNoChipThatWouldBeRefused() {
        var snapshot = AwsTestSupport.snapshot("one", com.tracelink.appsec.watchtower.core.scan.code.CodeScanType.PULL_REQUEST);
        var index = new AwsSecuritySourceIndex(snapshot.context().commit(), "sha", List.of(new AwsSecuritySourceIndex.File("src/a.java", "sha", 10), new AwsSecuritySourceIndex.File("src/b.java", "sha", 10)), Set.of("SQL_INJECTION"), "");
        var details = new AwsSecurityFindingMapper().map(AwsSecurityImporterTest.finding("one").toBuilder().name("Ordinary finding").riskType("SQL_INJECTION").build(), snapshot, "review", "job", index);
        assertEquals(List.of(0, 1), details.sourceLocations());
        var some = AwsSecurityReportController.hideSuppressedFiles(details, Set.of("src/a.java"));
        assertEquals(List.of(1), some.sourceLocations()); assertFalse(some.sensitive());
        var none = AwsSecurityReportController.hideSuppressedFiles(details, Set.of("src/a.java", "src/b.java"));
        assertEquals(List.of(), none.sourceLocations()); assertTrue(none.sensitive()); assertEquals(AwsSecurityReportController.HIDDEN_FILE_REASON, none.sensitivityReason());
        assertSame(details, AwsSecurityReportController.hideSuppressedFiles(details, Set.of("src/other.java")));
    }
    @Test void qualificationIsExactAndSecretAndUnknownTypesStaySuppressed() {
        var snapshot = AwsTestSupport.snapshot("one", com.tracelink.appsec.watchtower.core.scan.code.CodeScanType.PULL_REQUEST);
        var index = new AwsSecuritySourceIndex(snapshot.context().commit(), "sha", List.of(new AwsSecuritySourceIndex.File("src/a.java", "sha", 10)), Set.of("SQL_INJECTION"), "https://review.example.com");
        var mapper = new AwsSecurityFindingMapper();
        var finding = AwsSecurityImporterTest.finding("one").toBuilder().name("Ordinary finding").riskType("SQL_INJECTION").build();
        var details = mapper.map(finding, snapshot, "review", "job", index);
        assertFalse(details.sensitive()); assertEquals(List.of(0), details.sourceLocations()); assertEquals("https://review.example.com/space/code-reviews/review", details.providerUrl());
        assertTrue(mapper.map(finding.toBuilder().riskType("NEW_TYPE").build(), snapshot, "review", "job", index).sensitive());
        var secretIndex = new AwsSecuritySourceIndex(snapshot.context().commit(), "sha", index.files(), Set.of("HARDCODED_CREDENTIALS"), "");
        assertTrue(mapper.map(finding.toBuilder().riskType("HARDCODED_CREDENTIALS").build(), snapshot, "review", "job", secretIndex).sensitive());
        var prefixed = finding.toBuilder().codeLocations(CodeLocation.builder().filePath("archive/src/a.java").lineStart(1).lineEnd(1).build()).build();
        assertTrue(mapper.map(prefixed, snapshot, "review", "job", index).sensitive());
        assertNull(details.description()); assertNull(details.reasoning());
    }
    @Test void oldEmptySourceReceiptCanUseCurrentPolicyButNewEmptyReceiptRemainsClosed() {
        var controller = new AwsSecurityReportController(mock(AwsSecurityRunRepository.class), mock(AwsSecurityImporter.class),
            mock(AwsSecurityAssessmentService.class));
        ReflectionTestUtils.setField(controller, "evidencePolicy", new AwsSecurityEvidencePolicy("SECURITY_MISCONFIGURATION", ""));
        var index = new AwsSecuritySourceIndex("commit", "archive-sha", List.of(), Set.of(), "");
        for (String version : List.of("2-source-free-qualified", "3-source-free-aws-paths", AwsSecurityFindingMapper.VERSION)) {
            var retained = new com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails(
                "AWS_SECURITY_AGENT", "123456789012", "us-east-1", "space", "review", "job", "finding", null,
                version, "AWS finding", null, "SECURITY_MISCONFIGURATION", "MEDIUM", null, null, "HIGH", null, "ACTIVE",
                List.of(), List.of(), true, null, List.of(), "Source unavailable", null, null);
            assertEquals(!AwsSecurityFindingMapper.VERSION.equals(version),
                controller.currentSource(index, retained).permits("SECURITY_MISCONFIGURATION"));
        }
    }
    @Test void sourceSwitchOnAllowsEveryNonSecretTypeIncludingScansTakenWhileItWasOn() {
        // Dev 2026-10-22: the switch read "on" from the 7-type default, but Privilege escalation stayed locked.
        var policy = new AwsSecurityEvidencePolicy("SECURITY_MISCONFIGURATION", "");
        assertTrue(policy.sourceShown());
        assertTrue(policy.sourceRiskTypes().contains("PRIVILEGE_ESCALATION"));
        assertFalse(policy.sourceRiskTypes().stream().anyMatch(AwsSecurityEvidencePolicy::secretType));
        var controller = new AwsSecurityReportController(mock(AwsSecurityRunRepository.class), mock(AwsSecurityImporter.class),
            mock(AwsSecurityAssessmentService.class));
        ReflectionTestUtils.setField(controller, "evidencePolicy", policy);
        var pinnedWhileOn = new AwsSecuritySourceIndex("commit", "archive-sha", List.of(), Set.of("SECURITY_MISCONFIGURATION"), "");
        var retained = new com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails(
            "AWS_SECURITY_AGENT", "123456789012", "us-east-1", "space", "review", "job", "finding", null,
            AwsSecurityFindingMapper.VERSION, "AWS finding", null, "PRIVILEGE_ESCALATION", "HIGH", null, null, "MEDIUM", null, "ACTIVE",
            List.of(), List.of(), true, null, List.of(), "Source unavailable", null, null);
        assertTrue(controller.currentSource(pinnedWhileOn, retained).permits("PRIVILEGE_ESCALATION"));
        assertFalse(new AwsSecurityEvidencePolicy("", "").sourceShown());
    }
    @Test void lockedSourceSaysWhySecretOrSwitchedOff() {
        var snapshot = AwsTestSupport.snapshot("one", com.tracelink.appsec.watchtower.core.scan.code.CodeScanType.REPOSITORY);
        var mapper = new AwsSecurityFindingMapper();
        var finding = AwsSecurityImporterTest.finding("one").toBuilder().name("Role can be assumed").riskType("PRIVILEGE_ESCALATION").build();
        var off = new AwsSecuritySourceIndex(snapshot.context().commit(), "sha", List.of(), Set.of(), "");
        assertEquals(AwsSecurityFindingMapper.SOURCE_OFF_REASON, mapper.map(finding, snapshot, "review", "job", off).sensitivityReason());
        var secret = finding.toBuilder().riskType("HARDCODED_CREDENTIALS").build();
        assertEquals(AwsSecurityFindingMapper.SECRET_REASON, mapper.map(secret, snapshot, "review", "job", off).sensitivityReason());
    }
    @Test void awsExtractionPathsResolveOnlyToExactUploadedFiles() {
        var snapshot = AwsTestSupport.snapshot("one", com.tracelink.appsec.watchtower.core.scan.code.CodeScanType.REPOSITORY);
        String path = "wt-test-core/src/main/java/com/example/ImageScanResultService.java";
        var index = new AwsSecuritySourceIndex(snapshot.context().commit(), "archive-sha",
            List.of(new AwsSecuritySourceIndex.File(path, "file-sha", 8441)), Set.of("BUSINESS_LOGIC_VULNERABILITIES"), "");
        String prefix = "/tmp/opt/source_code/code_sc-17f8a652-ec30-413e-8b6d-db674ede51b0/";
        var original = AwsSecurityImporterTest.finding("one").toBuilder().name("Failed scans look clean")
            .riskType("BUSINESS_LOGIC_VULNERABILITIES")
            .codeLocations(CodeLocation.builder().filePath(prefix + path).lineStart(106).lineEnd(115).build(),
                CodeLocation.builder().filePath(prefix + "wt-test-core/src/main/java/com/example/Other.java").lineStart(1).lineEnd(2).build(),
                CodeLocation.builder().filePath(prefix + "../" + path).lineStart(1).lineEnd(2).build(),
                CodeLocation.builder().filePath("/other/root/" + path).lineStart(1).lineEnd(2).build()).build();
        var mapped = new AwsSecurityFindingMapper().map(original, snapshot, "review", "job", index);
        assertEquals(List.of(new com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location(path, 106, 115, null)), mapped.locations());
        assertEquals(List.of(0), mapped.sourceLocations());
        assertFalse(mapped.sensitive());
        assertEquals(3, mapped.omissions().stream().filter(s -> s.contains("Location did not match")).count());
        assertTrue(new AwsSecurityFindingMapper().map(original.toBuilder().name("Credential-shaped literal").build(),
            snapshot, "review", "job", index).sensitive());
    }
    @Test void webAppLinkCannotCarryCredentialsTokensOrAnUnreviewedPath() {
        for (String url : List.of("javascript:alert(1)", "https://user:pass@review.example.com", "https://review.example.com/?token=secret", "https://review.example.com/findings/one", "http://review.example.com"))
            assertThrows(IllegalArgumentException.class, () -> new AwsSecurityEvidencePolicy("", url));
        assertThrows(IllegalArgumentException.class, () -> new AwsSecurityEvidencePolicy("secret_detection", ""));
        assertEquals(AwsSecurityEvidencePolicy.AWS_LOGIN_GUIDE, new AwsSecurityEvidencePolicy("", "").webAppUrl());
    }
    @Test void sourceIsParentBoundPinnedHashVerifiedAndNeverCached() throws Exception {
        Path root = Files.createDirectory(temp.resolve("root")); Files.createDirectories(root.resolve("src"));
        byte[] source = "first\n<script>untrusted source</script>\nthird\n".getBytes(StandardCharsets.UTF_8);
        Files.write(root.resolve("src/a.java"), source);
        var archive = AwsSecurityInputStore.archive(root, temp.resolve("source.zip"));
        assertEquals(AwsSecurityInputStore.sha256(source), archive.index().getFirst().sha256());
        var gateway = mock(AwsSecurityClientGateway.class); var store = new AwsTestSupport.MemoryStore(); var importer = new AwsSecurityImporter(gateway, store);
        ReflectionTestUtils.setField(importer, "evidencePolicy", new AwsSecurityEvidencePolicy("SQL_INJECTION", "https://review.example.com"));
        var run = AwsTestSupport.run(); var snapshot = AwsSecuritySnapshot.decode(run.snapshotJson); run.sourceSha = archive.sha256();
        run.sourceIndexKey = importer.writeSourceIndex(run.id, snapshot.context().commit(), archive, () -> {});
        var finding = AwsSecurityImporterTest.finding("one").toBuilder().name("Ordinary finding").riskType("SQL_INJECTION")
            .codeLocations(CodeLocation.builder().filePath("src/a.java").lineStart(2).lineEnd(2).build()).build();
        when(gateway.list(any(), anyString(), any())).thenReturn(ListFindingsResponse.builder().findingsSummaries(FindingSummary.builder().findingId("one").build()).build());
        when(gateway.details(any(), anyList())).thenReturn(BatchGetFindingsResponse.builder().findings(finding).build());
        var imported = importer.importAll(run, () -> {}); run.artifactKey = imported.key();
        var occurrence = importer.page(imported.manifest(), 0).getFirst();
        var runs = mock(AwsSecurityRunRepository.class); when(runs.findByParentTypeAndParentIdOrderByCreatedAtAsc("pull_request", 1)).thenReturn(List.of(run));
        var controller = new AwsSecurityReportController(runs, importer, mock(AwsSecurityAssessmentService.class));
        var integrations = mock(ApiIntegrationService.class); var integration = mock(AbstractScmIntegrationEntity.class); var api = mock(IScmApi.class);
        when(integrations.findByLabel("bb")).thenReturn(integration); when(integration.createApi()).thenReturn(api);
        var local = mock(ScanReportReader.class); when(local.permitsSource("pull_request", 1, snapshot.context().commit(), "src/a.java")).thenReturn(true);
        ReflectionTestUtils.setField(controller, "integrations", integrations); ReflectionTestUtils.setField(controller, "localReports", local);
        when(api.boundedFileAtCommit(eq("repo"), eq(snapshot.context().commit()), eq("src/a.java"), anyInt())).thenReturn(source);
        var request = new MockHttpServletRequest("GET", "/scan/report/1/aws/findings/" + occurrence.key() + "/source"); var response = new MockHttpServletResponse();
        var excerpt = controller.source(1, occurrence.key(), 0, 0, request, response);
        assertEquals(List.of("first", "<script>untrusted source</script>", "third"), excerpt.lines());
        assertEquals(1, excerpt.startLine()); assertEquals(2, excerpt.flaggedStartLine());
        assertEquals(snapshot.context().commit(), excerpt.commit()); assertEquals("no-store", response.getHeader("Cache-Control"));
        when(local.secretLines("pull_request", 1, "src/a.java")).thenReturn(Set.of(2));
        var masked = controller.source(1, occurrence.key(), 0, 0, request, response);
        assertEquals(List.of("first", com.tracelink.appsec.watchtower.core.scan.code.report.CodeExcerpts.MASKED_LINE_TEXT, "third"), masked.lines());
        assertEquals(List.of(2), masked.maskedLines());
        when(local.secretLines("pull_request", 1, "src/a.java")).thenReturn(Set.of());
        assertThrows(ResponseStatusException.class, () -> controller.source(2, occurrence.key(), 0, 0, request, response));
        assertThrows(ResponseStatusException.class, () -> controller.source(1, occurrence.key(), 0, 1, request, response));
        when(api.boundedFileAtCommit(anyString(), anyString(), anyString(), anyInt())).thenReturn("changed branch".getBytes(StandardCharsets.UTF_8));
        assertEquals(409, assertThrows(ResponseStatusException.class, () -> controller.source(1, occurrence.key(), 0, 0, request, response)).getStatusCode().value());
        when(api.boundedFileAtCommit(anyString(), anyString(), anyString(), anyInt()))
            .thenThrow(new IOException("Pinned SCM input unavailable: HTTP 503"));
        var unavailable = assertThrows(ResponseStatusException.class,
            () -> controller.source(1, occurrence.key(), 0, 0, request, response));
        assertEquals(503, unavailable.getStatusCode().value());
        assertTrue(unavailable.getReason().contains("code host"));
        when(local.permitsSource(anyString(), anyLong(), anyString(), anyString())).thenReturn(false);
        clearInvocations(api);
        assertEquals(403, assertThrows(ResponseStatusException.class, () -> controller.source(1, occurrence.key(), 0, 0, request, response)).getStatusCode().value()); verifyNoInteractions(api);
        for (var bytes : store.objects.values()) try (var gzip = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(bytes))) { assertFalse(new String(gzip.readAllBytes(), StandardCharsets.UTF_8).contains("untrusted source")); }
    }
    @Test void completedLegacyScanLoadsOriginalTitleLocationsAndPinnedCodeWithoutReimport() throws Exception {
        var run = AwsTestSupport.run(); run.artifactKey = "published-artifact";
        var snapshot = AwsSecuritySnapshot.decode(run.snapshotJson);
        String path = "wt-test-core/src/main/java/example/ImageScanResultService.java";
        byte[] source = "first\nsecond\nthird\n".getBytes(StandardCharsets.UTF_8);
        var index = new AwsSecuritySourceIndex(snapshot.context().commit(), "archive-sha",
            List.of(new AwsSecuritySourceIndex.File(path, AwsSecurityInputStore.sha256(source), source.length)), Set.of(), "");
        var retained = new com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails(
            "AWS_SECURITY_AGENT", snapshot.profile().account(), snapshot.profile().region(), snapshot.profile().spaceId(),
            "review", "job", "one", null, "2-source-free-qualified", "AWS security finding: SQL_INJECTION", null,
            "SQL_INJECTION", "HIGH", null, null, "HIGH", null, "ACTIVE", List.of(), List.of("Invalid location omitted"),
            true, null, List.of(), "Source suppressed", null, null);
        String key = "a".repeat(64);
        var manifest = new AwsSecurityArtifact(2, run.id, snapshot, "COMPLETED", "COMPLETE", 1, 1, 1,
            List.of(), List.of(), 30, List.of("page"), null, java.util.Map.of(), java.util.Map.of());
        var importer = mock(AwsSecurityImporter.class);
        when(importer.manifest(run.artifactKey)).thenReturn(manifest);
        when(importer.page(manifest, 0)).thenReturn(List.of(new AwsSecurityArtifact.Occurrence(key, retained)));
        when(importer.sourceIndex(run)).thenReturn(index);
        var original = AwsSecurityImporterTest.finding("one").toBuilder().name("Failed scan looks clean")
            .description("The scan error is saved as a successful result.").riskType("SQL_INJECTION")
            .codeLocations(CodeLocation.builder().filePath("/tmp/opt/source_code/code_sc-17f8a652-ec30-413e-8b6d-db674ede51b0/" + path)
                .lineStart(2).lineEnd(2).build()).build();
        var gateway = mock(AwsSecurityClientGateway.class);
        when(gateway.details(any(), anyList())).thenReturn(BatchGetFindingsResponse.builder().findings(original).build());
        var runs = mock(AwsSecurityRunRepository.class);
        when(runs.findByParentTypeAndParentIdOrderByCreatedAtAsc("pull_request", 1)).thenReturn(List.of(run));
        var controller = new AwsSecurityReportController(runs, importer, mock(AwsSecurityAssessmentService.class));
        ReflectionTestUtils.setField(controller, "gateway", gateway);
        ReflectionTestUtils.setField(controller, "evidencePolicy", new AwsSecurityEvidencePolicy("SQL_INJECTION", ""));
        var integrations = mock(ApiIntegrationService.class); var integration = mock(AbstractScmIntegrationEntity.class); var api = mock(IScmApi.class);
        when(integrations.findByLabel("bb")).thenReturn(integration); when(integration.createApi()).thenReturn(api);
        when(api.boundedFileAtCommit(eq("repo"), eq(snapshot.context().commit()), eq(path), anyInt())).thenReturn(source);
        ReflectionTestUtils.setField(controller, "integrations", integrations);
        var local = mock(ScanReportReader.class); when(local.permitsSource("pull_request", 1, snapshot.context().commit(), path)).thenReturn(true);
        ReflectionTestUtils.setField(controller, "localReports", local);
        var request = new MockHttpServletRequest("GET", "/scan/report/1/aws/findings/" + key);
        var response = new MockHttpServletResponse();
        var detail = controller.detail(1, key, 0, request, response);
        assertTrue(detail.live()); assertEquals("Failed scan looks clean", detail.title());
        assertEquals("The scan error is saved as a successful result.", detail.description());
        assertEquals(path, detail.evidence().locations().getFirst().file());
        assertEquals("no-store", response.getHeader("Cache-Control"));
        assertEquals(path, controller.titles(1, 0, request, new MockHttpServletResponse()).get(key).file());
        var excerpt = controller.source(1, key, 0, 0, request, new MockHttpServletResponse());
        assertEquals(List.of("first", "second", "third"), excerpt.lines());
        when(gateway.details(any(), anyList())).thenReturn(BatchGetFindingsResponse.builder().findings(original.toBuilder().codeReviewJobId("other").build()).build());
        assertFalse(controller.detail(1, key, 0, request, new MockHttpServletResponse()).live());
        assertEquals(503, assertThrows(ResponseStatusException.class,
            () -> controller.source(1, key, 0, 0, request, new MockHttpServletResponse())).getStatusCode().value());
        when(gateway.details(any(), anyList())).thenReturn(BatchGetFindingsResponse.builder().findings(original.toBuilder()
            .name("Credential token AKIAFAKE exposed").description("Raw credential AKIAFAKE").build()).build());
        var sensitive = controller.detail(1, key, 0, request, new MockHttpServletResponse());
        assertEquals("SQL injection", sensitive.title());
        assertNull(sensitive.description());
        assertEquals(403, assertThrows(ResponseStatusException.class,
            () -> controller.source(1, key, 0, 0, request, new MockHttpServletResponse())).getStatusCode().value());
    }
    @Test void externalSortSpansSeveralMergePassesAndHasStableTieBreaks() throws Exception {
        var mapper = new AwsSecurityFindingMapper(); var run = AwsTestSupport.run(); var snapshot = AwsSecuritySnapshot.decode(run.snapshotJson);
        var values = new ArrayList<AwsSecurityArtifact.Occurrence>();
        for (int i = 0; i < 1701; i++) values.add(new AwsSecurityArtifact.Occurrence(String.format("%064d", i), mapper.map(AwsSecurityImporterTest.finding("f" + i).toBuilder().riskLevel(i % 2 == 0 ? "LOW" : "CRITICAL").confidence(i % 7 == 0 ? (String)null : i % 3 == 0 ? "LOW" : "HIGH").build(), snapshot, "review", "job")));
        var expected = values.stream().sorted(AwsSecurityFindingSort.ORDER).toList(); Collections.shuffle(values, new Random(9));
        var actual = new ArrayList<AwsSecurityArtifact.Occurrence>();
        try (var sort = new AwsSecurityFindingSort()) { for (var value : values) sort.add(value); sort.drain(actual::add, () -> {}); }
        assertEquals(expected, actual); assertEquals(1701, actual.size());
        assertEquals("CRITICAL", actual.getFirst().details().severity()); assertEquals("HIGH", actual.getFirst().details().confidence());
    }
    @Test void jobProgressPreservesStepsAndKnownGapsWithoutProviderProse() {
        var job=CodeReviewJob.builder().status("FAILED").title("secret title").overview("source snippet")
            .errorInformation(ErrorInformation.builder().code("ACCESS_DENIED").message("credential text").build())
            .steps(Step.builder().name("ANALYSIS").status("FAILED").createdAt(java.time.Instant.EPOCH).build()).build();
        var receipt=AwsSecurityJobReceipt.of(job); var json=receipt.encode();
        assertEquals(receipt,AwsSecurityJobReceipt.decode(json)); assertEquals(1,receipt.steps().size());
        assertEquals("NOT_EXPOSED",receipt.securityRequirementsRevision()); assertEquals("UNKNOWN",receipt.engineVersion());
        assertFalse(json.contains("secret title")); assertFalse(json.contains("source snippet")); assertFalse(json.contains("credential text"));
    }

    @Test void showSourceAllowsEveryRiskTypeAwsCodeReviewsReturnExceptSecretLikeOnes() {
        var allowed = new AwsSecurityEvidencePolicy("SQL_INJECTION", "").sourceRiskTypes();
        // These never showed source before: the old list had only seven of AWS's real types.
        for (String type : List.of("COMMAND_INJECTION", "CODE_INJECTION", "PATH_TRAVERSAL", "SERVER_SIDE_REQUEST_FORGERY",
            "XML_EXTERNAL_ENTITY", "INSECURE_DESERIALIZATION", "INFORMATION_DISCLOSURE", "SQL_INJECTION", "CROSS_SITE_SCRIPTING"))
            assertTrue(allowed.contains(type), type);
        assertTrue(allowed.contains("SECURITY_MISCONFIGURATION"), "names earlier versions listed stay allowed");
        for (String type : List.of("DEFAULT_CREDENTIALS", "UNKNOWN", "UNKNOWN_TO_SDK_VERSION"))
            assertFalse(allowed.contains(type), type + " must stay masked");
        assertTrue(allowed.stream().noneMatch(AwsSecurityEvidencePolicy::secretType));
        assertTrue(new AwsSecurityEvidencePolicy("", "").sourceRiskTypes().isEmpty(), "off still allows nothing");
    }
}
