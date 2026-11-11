package com.tracelink.appsec.module.awssecurity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

/** A form post from a report goes back to that report with a message; a JSON caller still gets the receipt. */
class AwsSecurityOperationsControllerTest {
    private final AwsSecurityPersistence persistence = mock(AwsSecurityPersistence.class);
    private final AwsSecurityRunRepository runs = mock(AwsSecurityRunRepository.class);
    private final AwsSecurityAuditRepository audit = mock(AwsSecurityAuditRepository.class);
    private final AwsSecurityOperationsController controller = new AwsSecurityOperationsController(persistence,
            mock(AwsSecuritySettings.class), mock(AwsSecurityClientGateway.class), runs, audit,
            mock(AwsSecurityReadiness.class), mock(AwsSecurityCapacity.class));
    private final Authentication actor = mock(Authentication.class);

    private AwsSecurityRun run() {
        var run = mock(AwsSecurityRun.class);
        run.id = "run-1";
        when(runs.findById("run-1")).thenReturn(Optional.of(run));
        when(actor.getName()).thenReturn("engineer");
        return run;
    }

    @Test
    void aBrowserFormPostIsSentBackToItsPageWithAMessageInsteadOfAnEmptyPage() {
        run();
        var flash = new RedirectAttributesModelMap();

        Object result = controller.operate("run-1", "reconcile", actor, "text/html,application/xhtml+xml,*/*;q=0.8", null,
                "https://watchtower.example/scan/report/158746?x=1", flash);

        assertInstanceOf(ModelAndView.class, result);
        assertEquals("redirect:/scan/report/158746?x=1", ((ModelAndView) result).getViewName());
        assertTrue(String.valueOf(flash.getFlashAttributes().get("success")).startsWith("Reconcile requested"));
        verify(persistence).scheduleRecovery("run-1");
        verify(audit).save(any(AwsSecurityAudit.class));
    }

    @Test
    void aBoostedFormPostIsSentBackWithAMessageEvenThoughItAcceptsAnything() {
        // Dev E2E E02: the page's htmx boost sends Accept */* with HX-Request; the JSON receipt it got
        // was swapped into the page and left it blank.
        run();
        var flash = new RedirectAttributesModelMap();

        Object result = controller.operate("run-1", "reconcile", actor, "*/*", "true",
                "https://watchtower.example/scan/report/158746", flash);

        assertInstanceOf(ModelAndView.class, result);
        assertEquals("redirect:/scan/report/158746", ((ModelAndView) result).getViewName());
        assertTrue(String.valueOf(flash.getFlashAttributes().get("success")).startsWith("Reconcile requested"));
    }

    @Test
    void aJsonCallerStillGetsTheReceipt() {
        run();

        Object result = controller.operate("run-1", "stop", actor, "application/json", null, null, new RedirectAttributesModelMap());

        assertEquals(Map.of("run", "run-1", "action", "stop", "state", "Requested"), result);
        verify(persistence).requestStop("run-1");
    }

    @Test
    void anUnknownRunIsNotFoundAndAnUnknownActionIsABadRequest() {
        run();

        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> controller.operate("missing", "stop", actor, null, null, null, new RedirectAttributesModelMap()));
        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> controller.operate("run-1", "explode", actor, null, null, null, new RedirectAttributesModelMap()));
    }

    @Test
    void theReturnAddressIsAlwaysAPathOnThisSite() {
        assertEquals("/aws-security/readiness/view", AwsSecurityOperationsController.backTo(null));
        assertEquals("/aws-security/readiness/view", AwsSecurityOperationsController.backTo("  "));
        assertEquals("/scan/report/9", AwsSecurityOperationsController.backTo("https://evil.example/scan/report/9"),
                "only the path is used, so the host of a forged referer is ignored");
        assertEquals("/aws-security/readiness/view", AwsSecurityOperationsController.backTo("https://x.example//evil.example/a"));
        assertEquals("/aws-security/readiness/view", AwsSecurityOperationsController.backTo("not a uri at all"));
        assertEquals("/aws-security/readiness/view", AwsSecurityOperationsController.backTo("mailto:someone"));
    }

    @Test
    void theSetupStepsTickWhenAReviewRuleIsInARulesetAndAScanHasRun() {
        when(runs.hasScanRun()).thenReturn(true);
        var provided = ruleset(true, true);
        var included = ruleset(false, true);
        when(rulesets.getRulesets()).thenReturn(java.util.List.of(provided, included));

        var model = readinessModel();

        assertEquals(true, model.get("awsReviewInRuleset"));
        assertEquals(true, model.get("awsHasScanRun"));
    }

    @Test
    void theModulesOwnRulesetAloneDoesNotCountAsAddingTheReviewRule() {
        var provided = ruleset(true, true);
        var other = ruleset(false, false);
        when(rulesets.getRulesets()).thenReturn(java.util.List.of(provided, other));

        assertEquals(false, readinessModel().get("awsReviewInRuleset"));
    }

    @Test
    void theSetupStepsStayOpenBeforeTheReviewRuleIsUsed() {
        var model = readinessModel();

        assertEquals(false, model.get("awsReviewInRuleset"));
        assertEquals(false, model.get("awsHasScanRun"));
    }

    private final com.tracelink.appsec.watchtower.core.ruleset.RulesetService rulesets =
            mock(com.tracelink.appsec.watchtower.core.ruleset.RulesetService.class);

    /** A ruleset whose effective rules include (or not) one AWS rule. */
    private static com.tracelink.appsec.watchtower.core.ruleset.RulesetDto ruleset(boolean provided, boolean runsAws) {
        var ruleset = mock(com.tracelink.appsec.watchtower.core.ruleset.RulesetDto.class);
        var rule = mock(com.tracelink.appsec.watchtower.core.rule.RuleDto.class);
        when(rule.getModule()).thenReturn(runsAws ? AwsSecurityModule.NAME : "Regex");
        when(ruleset.isProvided()).thenReturn(provided);
        when(ruleset.getAllRules()).thenReturn(java.util.Set.of(rule));
        return ruleset;
    }

    private Map<String, Object> readinessModel() {
        var access = mock(AwsSecuritySetupAccess.class);
        var controls = mock(com.tracelink.appsec.watchtower.core.module.ModuleControlService.class);
        var importer = mock(AwsSecurityImporter.class);
        var readiness = mock(AwsSecurityReadiness.class);
        when(readiness.check()).thenReturn(new AwsSecurityReadiness.Result(true, 0, "ok"));
        var page = new AwsSecurityOperationsController(persistence, mock(AwsSecuritySettings.class),
                mock(AwsSecurityClientGateway.class), runs, audit, readiness, mock(AwsSecurityCapacity.class));
        org.springframework.test.util.ReflectionTestUtils.setField(page, "rulesetService", rulesets);
        org.springframework.test.util.ReflectionTestUtils.setField(page, "setupAccess", access);
        org.springframework.test.util.ReflectionTestUtils.setField(page, "moduleControls", controls);
        org.springframework.test.util.ReflectionTestUtils.setField(page, "reportImporter", importer);
        org.springframework.test.util.ReflectionTestUtils.setField(page, "evidencePolicy",
                mock(AwsSecurityEvidencePolicy.class));
        org.springframework.test.util.ReflectionTestUtils.setField(page, "failurePolicyStore",
                mock(AwsSecurityFailurePolicyStore.class));
        when(actor.getName()).thenReturn("engineer");
        return page.readinessPage(null, actor).getModel();
    }

    @Test
    void anOutOfRangeReviewLimitComesBackWithAMessageAndSavesNothing() {
        var flash = new RedirectAttributesModelMap();
        var access = mock(AwsSecuritySetupAccess.class);
        var capacity = mock(AwsSecurityCapacity.class);
        var page = new AwsSecurityOperationsController(persistence, mock(AwsSecuritySettings.class),
                mock(AwsSecurityClientGateway.class), runs, audit, mock(AwsSecurityReadiness.class), capacity);
        org.springframework.test.util.ReflectionTestUtils.setField(page, "setupAccess", access);
        when(actor.getName()).thenReturn("engineer");

        for (String bad : new String[] {"9", "0", "abc", ""}) {
            String view = page.updateSettings(bad, false, null, actor, flash);
            assertEquals("redirect:/aws-security/readiness/view?tab=settings", view);
            assertTrue(String.valueOf(flash.getFlashAttributes().get("failure")).contains("1 to 5"), bad);
        }
        verify(capacity, never()).save(anyInt(), anyString());
    }
}
