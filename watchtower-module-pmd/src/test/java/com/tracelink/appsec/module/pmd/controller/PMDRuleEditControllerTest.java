package com.tracelink.appsec.module.pmd.controller;

import java.util.Arrays;
import java.util.Collections;

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

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyEntity;
import com.tracelink.appsec.module.pmd.model.PMDRuleEntity;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
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
public class PMDRuleEditControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private RuleEditController ruleEditController;

	@MockBean
	private RuleService ruleService;

	@MockBean
	private PMDRuleService pmdRuleService;

	@MockBean
	private UserService userService;

	@MockBean
	private RulesetRepository rulesetRepository;

	@MockBean
	private RuleRepository ruleRepository;

	@Autowired
	private PMDRuleEditController pmdRuleEditController;

	private PMDCustomRuleDto pmdRule;

	@BeforeEach
	public void setup() {
		pmdRule = getPMDRuleDto();
	}

	@Test
	@WithMockUser(authorities = {PMDModule.PMD_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditPmdRule() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/pmd/edit")
				.param("id", pmdRule.getId().toString())
				.param("author", pmdRule.getAuthor()).param("name", "New Name")
				.param("message", pmdRule.getMessage())
				.param("externalUrl", pmdRule.getExternalUrl())
				.param("priority", pmdRule.getPriority().toString())
				.param("parserLanguage", pmdRule.getParserLanguage())
				.param("ruleClass", pmdRule.getRuleClass())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully edited rule."));
		ArgumentCaptor<PMDCustomRuleDto> argumentCaptor =
				ArgumentCaptor.forClass(PMDCustomRuleDto.class);
		BDDMockito.verify(pmdRuleService).editRule(argumentCaptor.capture());
		Assertions.assertEquals("New Name", argumentCaptor.getValue().getName());
	}

	@Test
	@WithMockUser(authorities = {PMDModule.PMD_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditPmdRuleNotFound() throws Exception {
		BDDMockito.doThrow(RuleNotFoundException.class).when(pmdRuleService)
				.editRule(BDDMockito.any(PMDCustomRuleDto.class));
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/pmd/edit")
				.param("id", pmdRule.getId().toString())
				.param("author", pmdRule.getAuthor()).param("name", "New Name")
				.param("message", pmdRule.getMessage())
				.param("externalUrl", pmdRule.getExternalUrl())
				.param("priority", pmdRule.getPriority().toString())
				.param("parserLanguage", pmdRule.getParserLanguage())
				.param("ruleClass", pmdRule.getRuleClass())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot edit rule.")));
	}

	@Test
	@WithMockUser(authorities = {PMDModule.PMD_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditPmdRuleValidateFailure() {
		String defaultMessage = "message";
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		BDDMockito.when(bindingResult.hasErrors()).thenReturn(true);
		BDDMockito.when(bindingResult.getFieldErrors())
				.thenReturn(Arrays.asList(new FieldError("", "", defaultMessage)));
		PMDCustomRuleDto rule = getPMDRuleDto();
		RedirectAttributes redirect = new RedirectAttributesModelMap();
		Assertions.assertEquals("redirect:/rule/edit/pmd/" + rule.getId(),
				pmdRuleEditController.editRule(rule, bindingResult,
						redirect));
		MatcherAssert.assertThat(
				String.valueOf(
						redirect.getFlashAttributes()
								.get(WatchtowerModelAndView.FAILURE_NOTIFICATION)),
				Matchers.containsString("Cannot edit rule"));
	}

	@Test
	@WithMockUser(authorities = {PMDModule.PMD_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditPmdRuleValidateFailureNameClash() {
		BDDMockito.when(
				ruleService.createsNameCollision(BDDMockito.anyLong(), BDDMockito.anyString()))
				.thenReturn(true);
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		PMDCustomRuleDto rule = getPMDRuleDto();
		Assertions.assertEquals("redirect:/rule/edit/pmd/" + rule.getId(),
				pmdRuleEditController.editRule(rule, bindingResult,
						new RedirectAttributesModelMap()));
	}

	public static PMDRuleEntity getPMDRule() {
		String author = "jdoe";
		String name = "Rule Name";
		String message = "This is a bad practice.";
		String url = "https://example.com";
		RulePriority priority = RulePriority.MEDIUM_HIGH;
		PMDRuleEntity rule = new PMDRuleEntity();
		rule.setAuthor(author);
		rule.setName(name);
		rule.setProvided(false);
		rule.setMessage(message);
		rule.setExternalUrl(url);
		rule.setPriority(priority);
		rule.setParserLanguage("java");
		rule.setRuleClass("net.sourceforge.pmd.lang.rule.XPathRule");
		PMDPropertyEntity property = new PMDPropertyEntity();
		property.setName("xpath");
		property.setValue("//PrimaryPrefix[Name[starts-with(@Image,\"System.out\")]]");
		rule.setProperties(Collections.singleton(property));
		return rule;
	}

	public static PMDCustomRuleDto getPMDRuleDto() {
		PMDCustomRuleDto dto = (PMDCustomRuleDto) getPMDRule().toDto();
		dto.setId(1L);
		return dto;
	}
}
