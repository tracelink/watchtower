package com.tracelink.appsec.module.regex.controller;

import java.util.Arrays;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.module.regex.model.RegexRuleEntity;
import com.tracelink.appsec.module.regex.service.RegexRuleService;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleEditController;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetRepository;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RegexRuleEditControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private RuleService ruleService;

	@MockBean
	private RuleEditController ruleEditController;

	@MockBean
	private RegexRuleService regexRuleService;

	@MockBean
	private UserService userService;

	@MockBean
	private RulesetRepository rulesetRepository;

	@MockBean
	private RuleRepository ruleRepository;

	@Autowired
	private RegexRuleEditController regexRuleEditController;


	private RegexCustomRuleDto regexRule;

	@BeforeEach
	public void setup() {
		regexRule = getRegexRuleDto();
	}

	@Test
	@WithMockUser(authorities = {RegexModule.REGEX_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditRegexRule() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/regex/edit")
				.param("id", regexRule.getId().toString())
				.param("author", regexRule.getAuthor()).param("name", "New Name")
				.param("message", regexRule.getMessage())
				.param("externalUrl", regexRule.getExternalUrl())
				.param("priority", regexRule.getPriority().toString())
				.param("fileExtension", regexRule.getFileExtension())
				.param("regexPattern", regexRule.getRegexPattern())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully edited rule."));
		ArgumentCaptor<RegexCustomRuleDto> argumentCaptor =
				ArgumentCaptor.forClass(RegexCustomRuleDto.class);
		BDDMockito.verify(regexRuleService).editRule(argumentCaptor.capture());
		Assertions.assertEquals("New Name", argumentCaptor.getValue().getName());
	}

	@Test
	@WithMockUser(authorities = {RegexModule.REGEX_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditRegexRuleNotFound() throws Exception {
		BDDMockito.doThrow(RuleNotFoundException.class).when(regexRuleService)
				.editRule(BDDMockito.any(RegexCustomRuleDto.class));
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/regex/edit")
				.param("id", regexRule.getId().toString())
				.param("author", regexRule.getAuthor()).param("name", "New Name")
				.param("message", regexRule.getMessage())
				.param("externalUrl", regexRule.getExternalUrl())
				.param("priority", regexRule.getPriority().toString())
				.param("fileExtension", regexRule.getFileExtension())
				.param("regexPattern", regexRule.getRegexPattern())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot edit rule.")));
	}

	@Test
	@WithMockUser(authorities = {RegexModule.REGEX_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditRegexRuleValidateFailure() {
		String defaultMessage = "message";
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		BDDMockito.when(bindingResult.hasErrors()).thenReturn(true);
		BDDMockito.when(bindingResult.getFieldErrors())
				.thenReturn(Arrays.asList(new FieldError("", "", defaultMessage)));
		RegexCustomRuleDto rule = getRegexRuleDto();
		RedirectAttributes redirect = new RedirectAttributesModelMap();
		Assertions.assertEquals("redirect:/rule/edit/regex/" + rule.getId(),
				regexRuleEditController.editRule(rule, bindingResult,
						redirect));
		MatcherAssert.assertThat(
				String.valueOf(
						redirect.getFlashAttributes()
								.get(WatchtowerModelAndView.FAILURE_NOTIFICATION)),
				Matchers.containsString("Cannot edit rule"));
	}

	@Test
	@WithMockUser(authorities = {RegexModule.REGEX_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditRegexRuleValidateNameCollision() {
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		BDDMockito.when(bindingResult.hasErrors()).thenReturn(false);
		BDDMockito.when(
				ruleService.createsNameCollision(BDDMockito.anyLong(), BDDMockito.anyString()))
				.thenReturn(true);
		RegexCustomRuleDto rule = getRegexRuleDto();
		RedirectAttributes redirect = new RedirectAttributesModelMap();
		Assertions.assertEquals("redirect:/rule/edit/regex/" + rule.getId(),
				regexRuleEditController.editRule(rule, bindingResult,
						redirect));
		MatcherAssert.assertThat(
				String.valueOf(
						redirect.getFlashAttributes()
								.get(WatchtowerModelAndView.FAILURE_NOTIFICATION)),
				Matchers.containsString("already exists"));
	}

	public static RegexRuleEntity getRegexRule() {
		String author = "jdoe";
		String name = "Rule Name";
		String message = "This is a bad practice.";
		String url = "https://example.com";
		RulePriority priority = RulePriority.MEDIUM_HIGH;
		RegexRuleEntity rule = new RegexRuleEntity();
		rule.setAuthor(author);
		rule.setName(name);
		rule.setProvided(false);
		rule.setMessage(message);
		rule.setExternalUrl(url);
		rule.setPriority(priority);
		rule.setFileExtension("");
		rule.setRegexPattern("[abcdef]");
		return rule;
	}

	public static RegexCustomRuleDto getRegexRuleDto() {
		RegexCustomRuleDto dto = (RegexCustomRuleDto) getRegexRule().toDto();
		dto.setId(2L);
		return dto;
	}
}
