package com.tracelink.appsec.watchtower.core.rule;

import java.util.Collections;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RuleEditControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private RuleService ruleService;

	@MockBean
	private RuleEditorService ruleManagerService;

	private RuleDto rule;

	@BeforeEach
	public void setup() {
		rule = new MockRuleEntity().toDto();
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
				.andExpect(
						MockMvcResultMatchers.flash().attribute(
								WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.is(Matchers.emptyOrNullString())));
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
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	public void testDeleteRuleNotFound() throws Exception {
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
