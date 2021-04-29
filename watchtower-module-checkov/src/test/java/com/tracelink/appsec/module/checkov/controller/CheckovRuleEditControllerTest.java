package com.tracelink.appsec.module.checkov.controller;

import java.util.Arrays;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import com.tracelink.appsec.module.checkov.CheckovModule;
import com.tracelink.appsec.module.checkov.model.CheckovRuleDto;
import com.tracelink.appsec.module.checkov.model.CheckovRuleTest;
import com.tracelink.appsec.module.checkov.service.CheckovRuleService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleEditController;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
public class CheckovRuleEditControllerTest {

	@MockBean
	private RuleEditController ruleEditController;

	@MockBean
	private RuleService ruleService;

	@MockBean
	private CheckovRuleService checkovRuleService;

	@Autowired
	private CheckovRuleEditController checkovController;

	@Test
	@WithMockUser(authorities = CheckovModule.CHECKOV_RULE_PRIVILEGE_NAME)
	public void testEditRule() throws Exception {
		CheckovRuleDto dto = CheckovRuleTest.createModelRule(true);
		RedirectAttributes attr = new RedirectAttributesModelMap();
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		BDDMockito.when(bindingResult.hasErrors()).thenReturn(false);
		BDDMockito.when(
				ruleService.createsNameCollision(BDDMockito.anyLong(), BDDMockito.anyString()))
				.thenReturn(false);
		checkovController.editRule(dto, bindingResult, attr);
		MatcherAssert.assertThat(
				attr.getFlashAttributes().get(WatchtowerModelAndView.SUCCESS_NOTIFICATION)
						.toString(),
				Matchers.containsString("Successfully"));
	}

	@Test
	@WithMockUser(authorities = CheckovModule.CHECKOV_RULE_PRIVILEGE_NAME)
	public void testEditRuleNotFound() throws Exception {
		CheckovRuleDto dto = CheckovRuleTest.createModelRule(true);
		RedirectAttributes attr = new RedirectAttributesModelMap();
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		BDDMockito.when(bindingResult.hasErrors()).thenReturn(false);
		BDDMockito.when(
				ruleService.createsNameCollision(BDDMockito.anyLong(), BDDMockito.anyString()))
				.thenReturn(false);
		BDDMockito.willThrow(RuleNotFoundException.class).given(checkovRuleService)
				.editRule(BDDMockito.any());
		checkovController.editRule(dto, bindingResult, attr);
		MatcherAssert.assertThat(
				attr.getFlashAttributes().get(WatchtowerModelAndView.FAILURE_NOTIFICATION)
						.toString(),
				Matchers.containsString("Cannot edit rule"));
	}

	@Test
	@WithMockUser(authorities = CheckovModule.CHECKOV_RULE_PRIVILEGE_NAME)
	public void testEditRuleBindingErrors() throws Exception {
		String message = "errorMessage";
		CheckovRuleDto dto = CheckovRuleTest.createModelRule(true);
		RedirectAttributes attr = new RedirectAttributesModelMap();
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		BDDMockito.when(bindingResult.hasErrors()).thenReturn(true);
		BDDMockito.when(bindingResult.getFieldErrors())
				.thenReturn(Arrays.asList(new FieldError("", "", message)));
		checkovController.editRule(dto, bindingResult, attr);
		MatcherAssert.assertThat(
				attr.getFlashAttributes().get(WatchtowerModelAndView.FAILURE_NOTIFICATION)
						.toString(),
				Matchers.allOf(
						Matchers.containsString("Cannot edit rule"),
						Matchers.containsString(message)));
	}

	@Test
	@WithMockUser(authorities = CheckovModule.CHECKOV_RULE_PRIVILEGE_NAME)
	public void testEditRuleCollision() throws Exception {
		CheckovRuleDto dto = CheckovRuleTest.createModelRule(true);
		RedirectAttributes attr = new RedirectAttributesModelMap();
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		BDDMockito.when(bindingResult.hasErrors()).thenReturn(false);
		BDDMockito.when(
				ruleService.createsNameCollision(BDDMockito.anyLong(), BDDMockito.anyString()))
				.thenReturn(true);
		checkovController.editRule(dto, bindingResult, attr);
		MatcherAssert.assertThat(
				attr.getFlashAttributes().get(WatchtowerModelAndView.FAILURE_NOTIFICATION)
						.toString(),
				Matchers.allOf(
						Matchers.containsString("Cannot edit rule"),
						Matchers.containsString("already exists")));
	}
}
