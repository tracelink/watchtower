package com.tracelink.appsec.module.awssecurity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.Optional;
import org.junit.jupiter.api.*;
import org.springframework.test.util.ReflectionTestUtils;
import com.tracelink.appsec.module.awssecurity.AwsPrDecision.FailurePolicy;

class AwsSecurityFailurePolicyStoreTest {
    AwsSecurityPermitRepository permits; AwsSecurityAuditRepository audit; AwsSecurityPermit row;
    private AwsSecurityFailurePolicyStore store(FailurePolicy deployment) {
        permits=mock(AwsSecurityPermitRepository.class);audit=mock(AwsSecurityAuditRepository.class);row=new AwsSecurityPermit();
        when(permits.findById(1)).thenReturn(Optional.of(row));when(permits.locked()).thenReturn(row);
        var store=new AwsSecurityFailurePolicyStore(deployment);
        ReflectionTestUtils.setField(store,"permits",permits);ReflectionTestUtils.setField(store,"audit",audit);
        return store;
    }
    @Test void passingWhenAwsCannotFinishIsTheDefaultSoABrokenAwsNeverBlocksDevelopers() {
        assertEquals(FailurePolicy.PASS_ON_ERROR,store(FailurePolicy.PASS_ON_ERROR).current());
        assertTrue(store(FailurePolicy.PASS_ON_ERROR).passOnError());
    }
    @Test void theOldUndecidedPlaceholderMeansTheDefault() {
        assertEquals(FailurePolicy.PASS_ON_ERROR,store(FailurePolicy.UNDECIDED).current());
        var store=store(FailurePolicy.UNDECIDED);row.failurePolicy="UNDECIDED";
        assertEquals(FailurePolicy.PASS_ON_ERROR,store.current());
    }
    @Test void aDeploymentValueOfKeepIncompleteIsTheStartingPointUntilTheSettingIsSaved() {
        var store=store(FailurePolicy.KEEP_INCOMPLETE);
        assertEquals(FailurePolicy.KEEP_INCOMPLETE,store.current());
        row.failurePolicy="PASS_ON_ERROR";
        assertEquals(FailurePolicy.PASS_ON_ERROR,store.current(),"the saved choice wins over the deployment value");
    }
    @Test void anUnreadableSavedValueFallsBackInsteadOfBreakingPublishing() {
        var store=store(FailurePolicy.PASS_ON_ERROR);row.failurePolicy="SOMETHING_ELSE";
        assertEquals(FailurePolicy.PASS_ON_ERROR,store.current());
    }
    @Test void savingTheSwitchStoresBothChoicesAndAuditsEachChange() {
        var store=store(FailurePolicy.PASS_ON_ERROR);
        assertTrue(store.savePassOnError(false,"admin"));
        assertEquals("KEEP_INCOMPLETE",row.failurePolicy);assertFalse(store.passOnError());
        assertTrue(store.savePassOnError(true,"admin"));
        assertEquals("PASS_ON_ERROR",row.failurePolicy);assertTrue(store.passOnError());
        verify(audit,times(2)).save(any());
    }
    @Test void anUnchangedSwitchWritesNothing() {
        var store=store(FailurePolicy.PASS_ON_ERROR);
        assertFalse(store.savePassOnError(true,"admin"));
        assertNull(row.failurePolicy);verifyNoInteractions(audit);
    }
}
