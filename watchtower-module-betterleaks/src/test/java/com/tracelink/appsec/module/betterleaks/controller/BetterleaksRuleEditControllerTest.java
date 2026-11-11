package com.tracelink.appsec.module.betterleaks.controller;

import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.module.betterleaks.service.BetterleaksRuleService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleEditController;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
public class BetterleaksRuleEditControllerTest {

	@MockitoBean
	private RuleEditController ruleEditController;

	@MockitoBean
	private RuleService ruleService;

	@MockitoBean
	private BetterleaksRuleService betterleaksRuleService;

	@Autowired
	private BetterleaksRuleEditController controller;

	private static BetterleaksProvidedRuleDto edit() {
		BetterleaksProvidedRuleDto dto = new BetterleaksProvidedRuleDto();
		dto.setId(7L);
		dto.setPriority(RulePriority.MEDIUM);
		return dto;
	}

	private static BindingResult bindingResult(FieldError... errors) {
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		BDDMockito.when(bindingResult.hasErrors()).thenReturn(errors.length > 0);
		BDDMockito.when(bindingResult.getFieldErrors()).thenReturn(List.of(errors));
		return bindingResult;
	}

	private static String flash(RedirectAttributes attributes, String key) {
		Object value = attributes.getFlashAttributes().get(key);
		return value == null ? null : value.toString();
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.RULE_EDITOR_PRIVILEGE_NAME)
	public void testEditSavesThePriorityAndRedirectsToTheRule() throws Exception {
		RedirectAttributes attributes = new RedirectAttributesModelMap();

		String view = controller.editRule(edit(), bindingResult(), attributes);

		BDDMockito.verify(betterleaksRuleService).editProvidedRule(BDDMockito.any());
		MatcherAssert.assertThat(flash(attributes, WatchtowerModelAndView.SUCCESS_NOTIFICATION),
				Matchers.containsString("Successfully"));
		Assertions.assertEquals(RuleEditController.RULE_EDIT_REDIRECT + "/betterleaks/7", view);
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.RULE_EDITOR_PRIVILEGE_NAME)
	public void testMissingRuleIsReportedNotThrown() throws Exception {
		BDDMockito.willThrow(new RuleNotFoundException("No such Betterleaks rule exists."))
				.given(betterleaksRuleService).editProvidedRule(BDDMockito.any());
		RedirectAttributes attributes = new RedirectAttributesModelMap();

		controller.editRule(edit(), bindingResult(), attributes);

		MatcherAssert.assertThat(flash(attributes, WatchtowerModelAndView.FAILURE_NOTIFICATION),
				Matchers.containsString("Cannot edit rule"));
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.RULE_EDITOR_PRIVILEGE_NAME)
	public void testBindingErrorsAreReportedWithoutSaving() throws Exception {
		RedirectAttributes attributes = new RedirectAttributesModelMap();

		controller.editRule(edit(), bindingResult(new FieldError("rule", "priority", "bad")),
				attributes);

		BDDMockito.verifyNoInteractions(betterleaksRuleService);
		MatcherAssert.assertThat(flash(attributes, WatchtowerModelAndView.FAILURE_NOTIFICATION),
				Matchers.allOf(Matchers.containsString("Cannot edit rule"),
						Matchers.containsString("bad")));
	}
}
