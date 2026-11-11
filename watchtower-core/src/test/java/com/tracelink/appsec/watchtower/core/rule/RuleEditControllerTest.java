package com.tracelink.appsec.watchtower.core.rule;

import java.util.Collections;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RuleEditControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private RuleService ruleService;

	@MockitoBean
	private RuleEditorService ruleManagerService;

	private MockRuleEntity ruleEntity;
	private RuleDto rule;


	@BeforeEach
	public void setup() {
		ruleEntity = new MockRuleEntity();
		rule = ruleEntity.toDto();
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testGetRuleEdit() throws Exception {
		BDDMockito.when(ruleManagerService.getDefaultRuleEditModule())
				.thenReturn("mock");
		mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit"))
				.andExpect(
						MockMvcResultMatchers.redirectedUrl("/rule/edit/mock"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testGetRuleEditNoDefault() throws Exception {
		BDDMockito.when(ruleManagerService.getDefaultRuleEditModule())
				.thenReturn(null);
		mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit"))
				.andExpect(
						MockMvcResultMatchers.redirectedUrl("/"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("no modules configured")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testGetRuleEditByModule() throws Exception {
		RuleEditModelAndView mav = new RuleEditModelAndView(null);
		mav.addObject("modules", Collections.singleton(""));
		mav.addObject("rules", Collections.singleton(BDDMockito.mock(RuleDto.class)));
		mav.addObject("activeModule", "");
		mav.addObject("activeRule", null);
		BDDMockito
				.when(ruleManagerService.getRuleEditModelAndView(BDDMockito.anyString(),
						BDDMockito.isNull()))
				.thenReturn(mav);

		mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit/test"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.not(Matchers.containsString("No rule modules are configured."))))
				.andExpect(
						MockMvcResultMatchers.flash().attribute(
								WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.is(Matchers.emptyOrNullString())));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testGetRuleEditByModuleRendersCompactNoRulesState() throws Exception {
		RuleEditModelAndView mav = new RuleEditModelAndView(null);
		mav.addObject("modules", Collections.singleton("test"));
		mav.addObject("rules", Collections.emptyList());
		mav.addObject("activeModule", "test");
		mav.addObject("activeRule", null);
		BDDMockito.when(ruleManagerService.getRuleEditModelAndView("test", null)).thenReturn(mav);

		mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit/test"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("There are no rules configured for this module.")))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.not(Matchers.containsString("No rule modules are configured."))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testGetRuleEditByModuleError() throws Exception {
		String message = "Not Found";
		String view = "mock";
		BDDMockito
				.when(ruleManagerService.getRuleEditModelAndView(BDDMockito.anyString(),
						BDDMockito.isNull()))
				.thenThrow(new RuleNotFoundException(message));
		BDDMockito.when(ruleManagerService.getDefaultRuleEditModule())
				.thenReturn(view);
		mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit/test"))
				.andExpect(
						MockMvcResultMatchers.flash().attribute(
								WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.is(message)))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/rule/edit/" + view));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testGetRuleEditByRule() throws Exception {
		RuleEditModelAndView mav = new RuleEditModelAndView(null);
		mav.addObject("modules", Collections.singleton(""));
		mav.addObject("rules", Collections.singleton(BDDMockito.mock(RuleDto.class)));
		mav.addObject("activeModule", "");
		mav.addObject("activeRule", null);
		BDDMockito
				.when(ruleManagerService.getRuleEditModelAndView(BDDMockito.anyString(),
						BDDMockito.anyLong()))
				.thenReturn(mav);
		mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit/test/1"))
				.andExpect(
						MockMvcResultMatchers.flash().attribute(
								WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.is(Matchers.emptyOrNullString())));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testGetRuleEditByRuleActiveRule() throws Exception {
		// No other test in this class ever sets activeRule to a non-null value, so none of them
		// render the Delete Rule button/dialog branch (th:if="${activeRule!=null}") or the
		// th:replace="~{${ruleView}}" inclusion - both added/changed in the Material Web
		// conversion. "rule-mgmt/mock" is the existing test-resource fragment other tests in
		// this module already point ruleView at.
		RuleEditModelAndView mav = new RuleEditModelAndView("rule-mgmt/mock");
		mav.addObject("modules", Collections.singleton("test"));
		mav.addObject("rules", Collections.singleton(rule));
		mav.addObject("activeModule", "test");
		mav.addObject("activeRule", rule);
		BDDMockito
				.when(ruleManagerService.getRuleEditModelAndView(BDDMockito.anyString(),
						BDDMockito.anyLong()))
				.thenReturn(mav);

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit/test/1"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(mvcResult);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testGetRuleEditByRuleBadModule() throws Exception {
		String message = "NotFound";
		String view = "mock";
		BDDMockito
				.when(ruleManagerService.getRuleEditModelAndView(BDDMockito.anyString(),
						BDDMockito.anyLong()))
				.thenThrow(new ModuleNotFoundException(message));
		BDDMockito.when(ruleManagerService.getDefaultRuleEditModule())
				.thenReturn(view);

		mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit/test/1"))
				.andExpect(
						MockMvcResultMatchers.flash().attribute(
								WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.is(message)))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/rule/edit/" + view));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testGetRuleEditByRuleBadRule() throws Exception {
		String message = "NotFound";
		String module = "test";
		BDDMockito
				.when(ruleManagerService.getRuleEditModelAndView(BDDMockito.anyString(),
						BDDMockito.anyLong()))
				.thenThrow(new RuleNotFoundException(message));

		mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit/" + module + "/1"))
				.andExpect(
						MockMvcResultMatchers.flash().attribute(
								WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.is(message)))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/rule/edit/" + module));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testDeleteRule() throws Exception {
		BDDMockito.when(ruleService.getRule(BDDMockito.anyLong())).thenReturn(ruleEntity);
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rule/edit/regex/delete")
						.param("ruleId", rule.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully deleted rule."));

		BDDMockito.verify(ruleService).deleteRule(rule.getId());
	}

	@Test
	@WithMockUser(username = "reviewer", authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testStewardshipFormBindsAndUsesAuthenticatedReviewer() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/regex/1/stewardship")
				.param("state", "DEPRECATED").param("owner", "security-team")
				.param("reviewBy", "2026-12-01").param("cwe", "CWE-79").param("category", "Web")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/rule/edit/regex/1"));
		BDDMockito.verify(ruleService).updateStewardship(1, "regex",
				new RuleStewardshipUpdate(RuleState.DEPRECATED, "security-team",
						java.time.LocalDate.of(2026, 12, 1), "CWE-79", "Web"), "reviewer");
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testStewardshipRequiresCsrf() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/regex/1/stewardship").param("state", "RETIRED"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
		BDDMockito.verify(ruleService, BDDMockito.never()).updateStewardship(
				BDDMockito.anyLong(), BDDMockito.anyString(), BDDMockito.any(), BDDMockito.anyString());
	}

	@Test
	@WithMockUser
	public void testStewardshipRequiresRuleModify() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/regex/1/stewardship")
				.param("state", "RETIRED").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
		BDDMockito.verify(ruleService, BDDMockito.never()).updateStewardship(
				BDDMockito.anyLong(), BDDMockito.anyString(), BDDMockito.any(), BDDMockito.anyString());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testDeleteRuleNotFound() throws Exception {
		BDDMockito.when(ruleService.getRule(BDDMockito.anyLong())).thenReturn(ruleEntity);
		BDDMockito.doThrow(RuleNotFoundException.class).when(ruleService).deleteRule(rule.getId());
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rule/edit/pmd/delete")
						.param("ruleId", rule.getId().toString())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(
						MockMvcResultMatchers.flash()
								.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
										Matchers.containsString("Cannot delete rule.")));
	}

}
