package com.tracelink.appsec.module.json.controller;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
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

import com.tracelink.appsec.module.json.JsonModule;
import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.json.service.JsonRuleService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class JsonRuleEditControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private RuleService ruleService;

	@MockBean
	private JsonRuleService jsonRuleService;

	@Test
	@WithMockUser(authorities = {JsonModule.JSON_RULE_EDITOR_PRIVILEGE_NAME})
	public void testEditRegexRule() throws Exception {
		BDDMockito.when(
				ruleService.createsNameCollision(BDDMockito.anyLong(), BDDMockito.anyString()))
				.thenReturn(false);
		String ruleName = "RuleName";
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/json")
				.param("id", "1")
				.param("author", "author")
				.param("name", ruleName)
				.param("message", "messsage")
				.param("externalUrl", "ext")
				.param("priority", RulePriority.MEDIUM.name())
				.param("fileExtension", "")
				.param("query", "$")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully edited rule."));
		ArgumentCaptor<JsonRuleDto> argumentCaptor =
				ArgumentCaptor.forClass(JsonRuleDto.class);
		BDDMockito.verify(jsonRuleService).editRule(argumentCaptor.capture());
		Assertions.assertEquals(ruleName, argumentCaptor.getValue().getName());
	}

	@Test
	@WithMockUser(authorities = {JsonModule.JSON_RULE_EDITOR_PRIVILEGE_NAME})
	public void testEditRegexRuleInvalid() throws Exception {
		BDDMockito.when(
				ruleService.createsNameCollision(BDDMockito.anyLong(), BDDMockito.anyString()))
				.thenReturn(false);
		String ruleName = "RuleName";
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/json")
				.param("id", "1")
				.param("author", "")
				.param("name", ruleName)
				.param("message", "messsage")
				.param("externalUrl", "ext")
				.param("priority", RulePriority.MEDIUM.name())
				.param("fileExtension", "")
				.param("query", "$")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Author cannot be empty")));
	}

	@Test
	@WithMockUser(authorities = {JsonModule.JSON_RULE_EDITOR_PRIVILEGE_NAME})
	public void testEditRegexRuleNameCollision() throws Exception {
		BDDMockito.when(
				ruleService.createsNameCollision(BDDMockito.anyLong(), BDDMockito.anyString()))
				.thenReturn(true);
		String ruleName = "RuleName";
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/json")
				.param("id", "1")
				.param("author", "author")
				.param("name", ruleName)
				.param("message", "messsage")
				.param("externalUrl", "ext")
				.param("priority", RulePriority.MEDIUM.name())
				.param("fileExtension", "")
				.param("query", "$")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString(
								"A rule with the name \"" + ruleName + "\" already exists.")));
	}

}
