package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import software.amazon.awssdk.services.securityagent.model.*;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;

class AwsSecurityImporterTest {
    static Finding finding(String id) { return Finding.builder().findingId(id).agentSpaceId("space").codeReviewId("review").codeReviewJobId("job")
        .riskLevel("CRITICAL").confidence("HIGH").validationStatus("NOT_VALIDATED").riskScore("9.8")
        .name("secret AKIAFAKE do not retain").description("```java\nsecret();\n``` https://x/?token=secret")
        .reasoning("<script>secret()</script>").attackScript("execute secret")
        .codeLocations(CodeLocation.builder().filePath("src/a.java").lineStart(2).lineEnd(7).label("source literal").build(),
            CodeLocation.builder().filePath("src/b.java").lineStart(10).lineEnd(12).build(),
            CodeLocation.builder().filePath("../outside").lineStart(1).lineEnd(1).build()).build(); }
    @Test void importsEveryPageDeduplicatesAndPreservesContextAndAnchors() throws Exception {
        var gateway=mock(AwsSecurityClientGateway.class);var store=new AwsTestSupport.MemoryStore();var importer=new AwsSecurityImporter(gateway,store);var run=AwsTestSupport.run();
        run.diffIndexKey=importer.writeDiffIndex(run.id,"diff --git a/src/b.java b/src/b.java\n--- a/src/b.java\n+++ b/src/b.java\n@@ -10 +10 @@\n-old\n+new\n".getBytes(StandardCharsets.UTF_8),()->{});
        when(gateway.list(any(),eq("job"),isNull())).thenReturn(ListFindingsResponse.builder().findingsSummaries(FindingSummary.builder().findingId("one").build()).nextToken("next").build());
        when(gateway.list(any(),eq("job"),eq("next"))).thenReturn(ListFindingsResponse.builder().findingsSummaries(FindingSummary.builder().findingId("one").build(),FindingSummary.builder().findingId("two").build()).build());
        when(gateway.details(any(),anyList())).thenReturn(BatchGetFindingsResponse.builder().findings(finding("one"),finding("two")).build());
        var result=importer.importAll(run,()->{});assertEquals(2,result.manifest().summaryPages());assertEquals(2,result.manifest().imported());assertEquals("COMPLETE",result.manifest().importStatus());assertEquals(30,result.manifest().providerFindingCap());
        var findings=importer.page(result.manifest(),0);assertNotEquals(findings.get(0).key(),findings.get(1).key());
        assertEquals(2,findings.getFirst().details().locations().size());assertEquals("src/b.java",findings.getFirst().changedLineAnchors().getFirst().file());
        assertEquals("CRITICAL",findings.getFirst().details().nativeSeverity());assertEquals("NOT_VALIDATED",findings.getFirst().details().validationStatus());
        String retained=new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(findings);
        assertFalse(retained.contains("AKIAFAKE"));assertFalse(retained.contains("secret()"));assertFalse(retained.contains("token=secret"));assertFalse(retained.contains("<script>"));assertTrue(retained.contains(AwsSecurityFindingMapper.VERSION));
    }
    @Test void missingAndWrongJobDetailsAreVisiblePartialAndRetried() throws Exception {
        var gateway=mock(AwsSecurityClientGateway.class);var importer=new AwsSecurityImporter(gateway,new AwsTestSupport.MemoryStore());
        when(gateway.list(any(),anyString(),isNull())).thenReturn(ListFindingsResponse.builder().findingsSummaries(FindingSummary.builder().findingId("one").build()).build());
        when(gateway.details(any(),anyList())).thenReturn(BatchGetFindingsResponse.builder().findings(finding("one").toBuilder().codeReviewJobId("other").build()).notFound("one").build());
        var result=importer.importAll(AwsTestSupport.run(),()->{});assertEquals("PARTIAL",result.manifest().importStatus());assertEquals(List.of("one"),result.manifest().missingIds());assertEquals(0,result.manifest().imported());verify(gateway,times(3)).details(any(),anyList());
    }
    @Test void unknownSeverityIsNeverProjectedToLowOrValidated() {
        var f=new AwsSecurityFindingMapper().map(finding("id").toBuilder().riskLevel("FUTURE").validationStatus((String)null).build(),AwsTestSupport.snapshot("one",CodeScanType.PULL_REQUEST),"review","job");
        assertEquals("UNKNOWN",f.severity());assertEquals("FUTURE",f.nativeSeverity());assertNull(f.legacyPriority());assertNull(f.validationStatus());assertTrue(f.sensitive());
    }
    @Test void repeatedPaginationTokenCannotPublishACompleteReport() {
        var gateway=mock(AwsSecurityClientGateway.class);var store=new AwsTestSupport.MemoryStore();var importer=new AwsSecurityImporter(gateway,store);
        when(gateway.list(any(),anyString(),any())).thenReturn(ListFindingsResponse.builder().nextToken("loop").build());
        assertThrows(IllegalStateException.class,()->importer.importAll(AwsTestSupport.run(),()->{}));assertTrue(store.objects.isEmpty());
    }
    @Test void failedOwnershipCannotWriteAnArtifact() {
        var importer=new AwsSecurityImporter(mock(AwsSecurityClientGateway.class),new AwsTestSupport.MemoryStore());
        assertThrows(AwsSecurityPersistence.LostOwnership.class,()->importer.importAll(AwsTestSupport.run(),()->{throw new AwsSecurityPersistence.LostOwnership();}));
    }
    @Test void csvNeutralizesFormulasAndSarifKeepsEveryLocation() {
        assertTrue(AwsSecurityReportController.csv("=HYPERLINK(x)").contains("'=HYPERLINK"));
        assertTrue(AwsSecurityReportController.csv("  =HYPERLINK(x)").contains("'  =HYPERLINK"));
        var details=new AwsSecurityFindingMapper().map(finding("id"),AwsTestSupport.snapshot("one",CodeScanType.PULL_REQUEST),"review","job");
        var sarif=AwsSecurityReportController.sarif(new AwsSecurityArtifact.Occurrence("key",details));
        assertEquals(2,((List<?>)sarif.get("locations")).size());assertEquals("error",sarif.get("level"));assertEquals(details,sarif.get("properties"));assertFalse(sarif.containsKey("codeFlows"));
    }
}
