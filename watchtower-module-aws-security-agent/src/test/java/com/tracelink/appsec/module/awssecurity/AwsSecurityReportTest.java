package com.tracelink.appsec.module.awssecurity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.securityagent.model.*;

class AwsSecurityReportTest {
    @Test void everyExportPreservesAnIncompleteZeroFindingAssessment() throws Exception {
        var run=AwsTestSupport.run();run.stage=AwsSecurityRun.Stage.FAILED;run.artifactKey=null;run.statusReason="Provider failed <untrusted>";
        var runs=mock(AwsSecurityRunRepository.class);when(runs.findByParentTypeAndParentIdOrderByCreatedAtAsc("pull_request",1)).thenReturn(List.of(run));
        var controller=new AwsSecurityReportController(runs,mock(AwsSecurityImporter.class),mock(AwsSecurityAssessmentService.class));
        for(String format:List.of("json","sarif","csv","html")) {
            var request=new MockHttpServletRequest("GET","/scan/report/1/aws/export");var response=new MockHttpServletResponse();
            controller.export(1,format,request,response);String body=response.getContentAsString();
            assertTrue(body.contains("FAILED"));assertTrue(body.contains("UNAVAILABLE"));assertEquals("no-store",response.getHeader("Cache-Control"));
            if(format.equals("json")) assertEquals(0,new ObjectMapper().readTree(body).path("assessments").get(0).path("findings").size());
            if(format.equals("sarif")) assertEquals(0,new ObjectMapper().readTree(body).path("runs").get(0).path("results").size());
            if(format.equals("csv")) assertTrue(body.contains("\"assessment\""));
            if(format.equals("html")) { assertFalse(body.contains("<untrusted>"));assertTrue(body.contains("&lt;untrusted&gt;")); }
        }
    }
    @Test void exportsIncludeAllProviderPagesRatherThanTheCurrentUiPage() throws Exception {
        var gateway=mock(AwsSecurityClientGateway.class);var importer=new AwsSecurityImporter(gateway,new AwsTestSupport.MemoryStore());
        var summaries=java.util.stream.IntStream.range(0,101).mapToObj(i->FindingSummary.builder().findingId("finding-"+i).build()).toList();
        when(gateway.list(any(),anyString(),isNull())).thenReturn(ListFindingsResponse.builder().findingsSummaries(summaries).build());
        when(gateway.details(any(),anyList())).thenAnswer(i->{List<String> ids=i.getArgument(1);return BatchGetFindingsResponse.builder()
            .findings(ids.stream().map(AwsSecurityImporterTest::finding).toList()).build();});
        var run=AwsTestSupport.run();var artifact=importer.importAll(run,()->{});run.artifactKey=artifact.key();run.importedCount=101;run.stage=AwsSecurityRun.Stage.COMPLETE;
        assertEquals(2,artifact.manifest().pages().size());assertEquals(101,artifact.manifest().nativeSeverityCounts().get("CRITICAL"));
        var runs=mock(AwsSecurityRunRepository.class);when(runs.findByParentTypeAndParentIdOrderByCreatedAtAsc("pull_request",1)).thenReturn(List.of(run));
        var controller=new AwsSecurityReportController(runs,importer,mock(AwsSecurityAssessmentService.class));var response=new MockHttpServletResponse();
        controller.export(1,"json",new MockHttpServletRequest("GET","/scan/report/1/aws/export"),response);
        assertEquals(101,new ObjectMapper().readTree(response.getContentAsString()).path("assessments").get(0).path("findings").size());
        assertFalse(response.getContentAsString().contains("AKIAFAKE"));
    }
}
