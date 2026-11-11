package com.tracelink.appsec.module.awssecurity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.web.server.ResponseStatusException;

class AwsSecurityReviewDeletionTest {
    AwsSecurityRun run;AwsSecurityRunRepository runs;AwsSecurityClientGateway gateway;AwsSecurityAuditRepository audit;AwsSecurityReviewDeletion deletion;
    @BeforeEach void setup(){run=AwsTestSupport.run();run.stage=AwsSecurityRun.Stage.COMPLETE;run.cleanupComplete=true;run.artifactKey="saved";
        runs=mock(AwsSecurityRunRepository.class);gateway=mock(AwsSecurityClientGateway.class);audit=mock(AwsSecurityAuditRepository.class);when(runs.locked(run.id)).thenReturn(Optional.of(run));when(gateway.retire(any(),eq("review"))).thenReturn(true);
        deletion=new AwsSecurityReviewDeletion(runs,gateway,AwsTestSupport.settings(),audit);}
    @Test void explicitDeletionRetainsTheSavedReportAndIsIdempotent(){
        assertEquals("/scan/report/1",deletion.delete(run.id,"review","DELETE","admin"));assertTrue(run.providerDeleted);assertEquals("saved",run.artifactKey);assertEquals(AwsSecurityRun.Stage.COMPLETE,run.stage);verify(audit).save(any());
        deletion.delete(run.id,"review","DELETE","admin");verify(gateway,times(1)).retire(any(),eq("review"));
    }
    @Test void mismatchedIdAndMissingConfirmationNeverDeleteAnything(){
        assertThrows(ResponseStatusException.class,()->deletion.delete(run.id,"other","DELETE","admin"));assertThrows(ResponseStatusException.class,()->deletion.delete(run.id,"review","","admin"));verifyNoInteractions(gateway,audit);
    }
    @Test void activeUncertainAndUncleanedScansCannotBeDeleted(){
        run.stage=AwsSecurityRun.Stage.RUNNING;assertThrows(ResponseStatusException.class,()->deletion.delete(run.id,"review","DELETE","admin"));
        run.stage=AwsSecurityRun.Stage.COMPLETE;run.providerTerminal=false;assertThrows(ResponseStatusException.class,()->deletion.delete(run.id,"review","DELETE","admin"));
        run.providerTerminal=true;run.cleanupComplete=false;assertThrows(ResponseStatusException.class,()->deletion.delete(run.id,"review","DELETE","admin"));verifyNoInteractions(gateway,audit);
    }
    @Test void failedProviderDeletionIsNotRecordedAsSuccess(){
        when(gateway.retire(any(),anyString())).thenReturn(false);assertThrows(ResponseStatusException.class,()->deletion.delete(run.id,"review","DELETE","admin"));assertFalse(run.providerDeleted);verifyNoInteractions(audit);
    }
    @Test void aSharedReviewIsNeverDeletedForOneScan(){
        run.sharedReview=true;
        var failure=assertThrows(ResponseStatusException.class,()->deletion.delete(run.id,"review","DELETE","admin"));
        assertEquals(org.springframework.http.HttpStatus.CONFLICT,failure.getStatusCode());assertFalse(run.providerDeleted);verifyNoInteractions(gateway,audit);
    }
}
