package com.tracelink.appsec.module.awssecurity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.*;

class AwsSecurityReadinessTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void readOnlyChecksDoNotDependOnScannerActivation(boolean kms) {
        var s=kms ? AwsTestSupport.settings() : AwsTestSupport.settings("");
        var off=new AwsSecuritySettings(s.region(),s.account(),s.spaceId(),s.serviceRole(),s.inputBucket(),s.kmsKey(),s.logGroup(),s.installation(),s.queueUrl(),s.reviewSeconds());
        var identity=mock(StsClient.class);when(identity.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(GetCallerIdentityResponse.builder().account(s.account()).build());
        var gateway=mock(AwsSecurityClientGateway.class);var inputs=mock(AwsSecurityInputStore.class);
        assertTrue(new AwsSecurityReadiness(off,gateway,inputs,identity).check().ready());
        verify(inputs).readiness(off.profile());verify(gateway).readiness(off.profile());verify(gateway,never()).create(any(),any(),any());
    }
    @ParameterizedTest
    @ValueSource(strings = {"invalid", "alias/source", "arn:aws:kms:us-west-2:123456789012:key/one", "arn:aws:kms:us-east-1:999999999999:key/one"})
    void suppliedInvalidKmsKeyIsRejectedBeforeAnyAwsAccess(String key) {
        var identity = mock(StsClient.class);
        var gateway = mock(AwsSecurityClientGateway.class);
        var inputs = mock(AwsSecurityInputStore.class);
        assertFalse(new AwsSecurityReadiness(AwsTestSupport.settings(key), gateway, inputs, identity).check().ready());
        verifyNoInteractions(identity, gateway, inputs);
    }
    @Test void persistedProfilesKeepTheirEncryptionModeAndDifferentModesChangeRevision() {
        var original = AwsTestSupport.snapshot("one", CodeScanType.PULL_REQUEST);
        var s3Managed = new AwsSecuritySnapshot(original.context(), AwsTestSupport.settings("").profile(), original.rule(),
            original.ruleName(), original.blockingLevel(), original.policyRevision());
        assertEquals(original, AwsSecuritySnapshot.decode(original.encode()));
        assertEquals(s3Managed, AwsSecuritySnapshot.decode(s3Managed.encode()));
        assertTrue(AwsSecuritySnapshot.decode(original.encode()).profile().usesKms());
        assertFalse(AwsSecuritySnapshot.decode(s3Managed.encode()).profile().usesKms());
        assertNotEquals(original.profile().revision(), s3Managed.profile().revision());
    }
    @Test void wrongAccountStopsBeforeBucketAndProviderAccess() {
        var identity=mock(StsClient.class);when(identity.getCallerIdentity(any(GetCallerIdentityRequest.class))).thenReturn(GetCallerIdentityResponse.builder().account("000000000000").build());
        var gateway=mock(AwsSecurityClientGateway.class);var inputs=mock(AwsSecurityInputStore.class);
        assertFalse(new AwsSecurityReadiness(AwsTestSupport.settings(),gateway,inputs,identity).check().ready());verifyNoInteractions(gateway,inputs);
    }
}
