package com.tracelink.appsec.module.awssecurity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.mockito.ArgumentCaptor;
import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;

/** Ordinary activation contracts; no live AWS or migration tests. */
class AwsSecurityActivationTest {
    AwsSecurityPersistence persistence; AwsSecurityRepositorySettingsRepository permissions;
    ModuleControlService controls; AwsSecurityAssessmentService service; RulesetDto rules;
    final ScanExecutionContext context=AwsTestSupport.snapshot("activation",CodeScanType.REPOSITORY).context();
    @BeforeEach void setup() {
        persistence=mock(AwsSecurityPersistence.class);permissions=mock(AwsSecurityRepositorySettingsRepository.class);controls=mock(ModuleControlService.class);
        var importer=mock(AwsSecurityImporter.class);when(importer.sharedArtifacts()).thenReturn(true);
        service=new AwsSecurityAssessmentService(AwsTestSupport.settings(),permissions,mock(RepositoryRepository.class),mock(AwsSecurityRunRepository.class),persistence,importer,mock(PRScanResultService.class),mock(ApiIntegrationService.class),controls);
        when(persistence.enlist(any(),anyLong(),nullable(String.class))).thenReturn(AwsTestSupport.run());
        when(controls.enabled(AwsSecurityModule.NAME)).thenReturn(true);
        var permission=new AwsSecurityRepositorySettings();permission.permission=AwsSecurityRepositorySettings.Permission.ENABLED;when(permissions.findById(context.repositoryId())).thenReturn(Optional.of(permission));
        rules=new RulesetDto();rules.setBlockingLevel(RulePriority.HIGH);var rule=new AwsSecurityRuleDto();rule.setName("Security review");rule.setPriority(RulePriority.HIGH);rules.getRules().add(rule);
    }
    @Test void uiSwitchAndSelectedPolicyAllowScanWithoutRepositoryConfiguration() {
        assertTrue(service.selected(rules));service.prepareRepository(context,rules);
        verify(persistence).enlist(any(),anyLong(),isNull());verifyNoInteractions(permissions);
    }
    @Test void uiSwitchOffPreventsSubmissionEvenForAnAllowedRepository() {
        when(controls.enabled(AwsSecurityModule.NAME)).thenReturn(false);service.prepareRepository(context,rules);
        var reason=ArgumentCaptor.forClass(String.class);verify(persistence).enlist(any(),anyLong(),reason.capture());assertTrue(reason.getValue().contains("Scanner modules"));
        verifyNoInteractions(permissions);
    }
    @Test void historicalRepositoryOverridesAreNotAnotherActivationStep() {
        when(permissions.findById(context.repositoryId())).thenReturn(Optional.empty());service.prepareRepository(context,rules);
        verify(persistence).enlist(any(),anyLong(),isNull());verifyNoInteractions(permissions);
    }
    @Test void missingPolicyIsNeverSelectedOrEnlisted() {
        rules.getRules().clear();assertFalse(service.selected(rules));assertThrows(IllegalArgumentException.class,()->service.prepareRepository(context,rules));verifyNoInteractions(persistence);
    }
}
