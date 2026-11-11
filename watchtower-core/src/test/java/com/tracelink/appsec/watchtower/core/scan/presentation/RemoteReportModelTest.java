package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.*;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService;

class RemoteReportModelTest {
    @Test void awsPagesNeverReplaceOrDuplicateTheLocalFindings() {
        var service=mock(RemoteAssessmentService.class);var status=new RemoteAssessmentService.Status("run","COMPLETE",null,"sha",null,"review","job",140,0,true,true,null,3,Map.of());
        when(service.status("repository",7)).thenReturn(List.of(status));var local=mock(FindingPresentationModel.class);var aws=mock(FindingPresentationModel.class);
        when(aws.getSeverityFilterKey()).thenReturn("HIGH");when(aws.getId()).thenReturn("aws-one");when(service.findings("repository",7,1)).thenReturn(List.of(aws));
        var request=new MockHttpServletRequest();request.setParameter("providerPage","1");RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {var model=new WatchtowerModelAndView("fixture");assertEquals(List.of(local),RemoteReportModel.add(model,"repository",7,service,List.of(local)));assertEquals(List.of(aws),model.getModel().get("providerFindings"));assertEquals(3,model.getModel().get("providerPages"));assertEquals(140,model.getModel().get("providerImported"));
            assertEquals(List.of(aws,local),model.getModel().get("workspaceFindings"));}
        finally{RequestContextHolder.resetRequestAttributes();}
    }

    @Test void oneWorkspaceListsAwsAndLocalFindingsMostSevereFirst() {
        var high=mock(FindingPresentationModel.class);when(high.getSeverityValue()).thenReturn(1);
        var low=mock(FindingPresentationModel.class);when(low.getSeverityValue()).thenReturn(4);
        var awsMedium=mock(FindingPresentationModel.class);when(awsMedium.getSeverityValue()).thenReturn(2);
        assertEquals(List.of(high,awsMedium,low),RemoteReportModel.workspace(List.of(awsMedium),List.of(high,low)));
        assertEquals(List.of(low,high),RemoteReportModel.workspace(List.of(),List.of(low,high)));
    }
    @Test void byRuleCountsTheAwsRuleBesideLocalRules() {
        var status=new RemoteAssessmentService.Status("run","COMPLETE",null,"sha",null,"review","job",19,0,true,true,null,1,Map.of(),Map.of("Rule","Security review"),List.of());
        var rows=RemoteReportModel.withProviderRules(List.of(Map.entry("private-key",3)),List.of(status));
        assertEquals(List.of(Map.entry("AWS Security Agent · Security review",19),Map.entry("private-key",3)),rows);
        var none=new RemoteAssessmentService.Status("run","FAILED",null,"sha",null,null,null,0,0,false,false,null,0,Map.of());
        assertEquals(List.of(Map.entry("private-key",3)),RemoteReportModel.withProviderRules(List.of(Map.entry("private-key",3)),List.of(none)));
    }
}
