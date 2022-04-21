package com.tracelink.appsec.module.eslint.controller;

import java.util.Arrays;

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

import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.module.eslint.designer.EsLintRuleDesigner;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDtoTest;
import com.tracelink.appsec.module.eslint.service.EsLintRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class EsLintRuleDesignerControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private EsLintRuleDesigner ruleDesigner;

	@MockBean
	private RuleDesignerService ruleDesignerService;

	@MockBean
	EsLintRuleService ruleService;

	private EsLintCustomRuleDto esLintRule;

	@BeforeEach
	public void setup() {
		esLintRule = EsLintRuleDtoTest.getCustomEsLintRule();
	}

	@Test
	@WithMockUser(authorities = {EsLintModule.ESLINT_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testQuery() throws Exception {
		String sourceCode = "function foo() {\n\tconsole.log('foo');\n}";
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesigner
				.query(BDDMockito.anyString(), BDDMockito.anyString(), BDDMockito.anyList()))
				.thenReturn(mav);
		BDDMockito.when(ruleDesignerService.getKnownModulesForUser(BDDMockito.any()))
				.thenReturn(Arrays.asList("ESLint"));
		mockMvc.perform(MockMvcRequestBuilders.post("/designer/eslint/query")
				.param("sourceCode", sourceCode)
				.param("name", esLintRule.getName())
				.param("author", "jdoe")
				.param("externalUrl", esLintRule.getExternalUrl())
				.param("message", esLintRule.getMessage())
				.param("createFunction", esLintRule.getCreateFunction())
				.param("messages[0].key", esLintRule.getMessages().get(0).getKey())
				.param("messages[0].value", esLintRule.getMessages().get(0).getValue())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("designerView",
						Matchers.nullValue()))
				.andExpect(MockMvcResultMatchers.model().attribute("knownModules",
						Matchers.contains("ESLint")));
	}

	@Test
	@WithMockUser(authorities = {EsLintModule.ESLINT_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveCustomMissingRequiredFields() throws Exception {
		String sourceCode = "function foo() {\n\tconsole.log('foo');\n}";
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesigner.getDefaultRuleDesignerModelAndView()).thenReturn(mav);
		BDDMockito.when(ruleDesignerService.getKnownModulesForUser(BDDMockito.any()))
				.thenReturn(Arrays.asList("ESLint"));

		mockMvc.perform(MockMvcRequestBuilders.post("/designer/eslint/save")
				.param("sourceCode", sourceCode)
				.param("name", esLintRule.getName())
				.param("author", "jdoe")
				.param("message", esLintRule.getMessage())
				.param("createFunction", esLintRule.getCreateFunction())
				.param("messages[0].key", esLintRule.getMessages().get(0).getKey())
				.param("messages[0].value", esLintRule.getMessages().get(0).getValue())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("designerView",
						Matchers.nullValue()))
				.andExpect(MockMvcResultMatchers.model().attribute("knownModules",
						Matchers.contains("ESLint")))
				.andExpect(MockMvcResultMatchers.model().attribute("failure",
						Matchers.allOf(Matchers.containsString("Failed to validate rule."),
								Matchers.containsString("External URL cannot be null"))));
	}

	@Test
	@WithMockUser(authorities = {EsLintModule.ESLINT_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveCustomRule() throws Exception {
		String sourceCode = "function foo() {\n\tconsole.log('foo');\n}";
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesignerService.getKnownModulesForUser(BDDMockito.any()))
				.thenReturn(Arrays.asList("ESLint"));
		BDDMockito.when(ruleDesigner.query(BDDMockito.anyString(), BDDMockito.any()))
				.thenReturn(mav);
		mockMvc.perform(MockMvcRequestBuilders.post("/designer/eslint/save")
				.param("sourceCode", sourceCode)
				.param("name", esLintRule.getName())
				.param("author", "jdoe")
				.param("message", esLintRule.getMessage())
				.param("externalUrl", esLintRule.getExternalUrl())
				.param("priority", esLintRule.getPriority().toString())
				.param("createFunction", esLintRule.getCreateFunction())
				.param("messages[0].key", esLintRule.getMessages().get(0).getKey())
				.param("messages[0].value", esLintRule.getMessages().get(0).getValue())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("designerView",
						Matchers.nullValue()))
				.andExpect(MockMvcResultMatchers.model().attribute("knownModules",
						Matchers.contains("ESLint")))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION, Matchers.emptyOrNullString()));
	}

}
