package com.tracelink.appsec.module.eslint.controller;

import java.util.Arrays;
import java.util.Collections;

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

import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.module.eslint.designer.EsLintRuleDesigner;
import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.service.EsLintRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
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
		esLintRule = getEsLintRuleDto();
	}

	@Test
	@WithMockUser(authorities = {EsLintModule.ESLINT_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testQuery() throws Exception {
		String sourceCode = "function foo() {\n\tconsole.log('foo');\n}";
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesigner
				.query(BDDMockito.anyString(), BDDMockito.anyBoolean(), BDDMockito.anyString(),
						BDDMockito.anyString(), BDDMockito.anyList()))
				.thenReturn(mav);
		BDDMockito.when(ruleDesignerService.getKnownModulesForUser(BDDMockito.any()))
				.thenReturn(Arrays.asList("ESLint"));
		mockMvc.perform(MockMvcRequestBuilders.post("/designer/eslint/query")
				.param("sourceCode", sourceCode)
				.param("core", "false")
				.param("name", esLintRule.getName())
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
		BDDMockito.when(ruleDesigner
				.query(BDDMockito.anyString(), BDDMockito.anyBoolean(), BDDMockito.anyString(),
						BDDMockito.anyString(), BDDMockito.anyList()))
				.thenReturn(mav);
		BDDMockito.when(ruleDesignerService.getKnownModulesForUser(BDDMockito.any()))
				.thenReturn(Arrays.asList("ESLint"));
		mockMvc.perform(MockMvcRequestBuilders.post("/designer/eslint/save")
				.param("sourceCode", sourceCode)
				.param("core", "false")
				.param("name", esLintRule.getName())
				.param("createFunction", esLintRule.getCreateFunction())
				.param("messages[0].key", esLintRule.getMessages().get(0).getKey())
				.param("messages[0].value", esLintRule.getMessages().get(0).getValue())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("designerView",
						Matchers.nullValue()))
				.andExpect(MockMvcResultMatchers.model().attribute("knownModules",
						Matchers.contains("ESLint")))
				.andExpect(MockMvcResultMatchers.model().attribute("failure",
						Matchers.stringContainsInOrder("Failed to validate rule.",
								"External URL cannot be empty")));

	}

	@Test
	@WithMockUser(authorities = {EsLintModule.ESLINT_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveCoreMissingRequiredFields() throws Exception {
		String sourceCode = "function foo() {\n\tconsole.log('foo');\n}";
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesigner
				.query(BDDMockito.anyString(), BDDMockito.anyBoolean(), BDDMockito.anyString(),
						BDDMockito.anyString(), BDDMockito.anyList()))
				.thenReturn(mav);
		BDDMockito.when(ruleDesignerService.getKnownModulesForUser(BDDMockito.any()))
				.thenReturn(Arrays.asList("ESLint"));
		mockMvc.perform(MockMvcRequestBuilders.post("/designer/eslint/save")
				.param("sourceCode", sourceCode)
				.param("core", "true")
				.param("name", esLintRule.getName())
				.param("createFunction", esLintRule.getCreateFunction())
				.param("messages[0].key", esLintRule.getMessages().get(0).getKey())
				.param("messages[0].value", esLintRule.getMessages().get(0).getValue())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("designerView",
						Matchers.nullValue()))
				.andExpect(MockMvcResultMatchers.model().attribute("knownModules",
						Matchers.contains("ESLint")))
				.andExpect(MockMvcResultMatchers.model().attribute("failure",
						Matchers.stringContainsInOrder("Failed to validate rule.",
								"Priority cannot be null")));

	}

	@Test
	@WithMockUser(authorities = {EsLintModule.ESLINT_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveCoreException() throws Exception {
		String sourceCode = "function foo() {\n\tconsole.log('foo');\n}";
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesigner
				.query(BDDMockito.anyString(), BDDMockito.anyBoolean(), BDDMockito.anyString(),
						BDDMockito.anyString(), BDDMockito.anyList()))
				.thenReturn(mav);
		BDDMockito.when(ruleDesignerService.getKnownModulesForUser(BDDMockito.any()))
				.thenReturn(Arrays.asList("ESLint"));
		BDDMockito.doThrow(RuleDesignerException.class).when(ruleService)
				.saveRule(BDDMockito.any());
		mockMvc.perform(MockMvcRequestBuilders.post("/designer/eslint/save")
				.param("sourceCode", sourceCode)
				.param("core", "true")
				.param("name", esLintRule.getName())
				.param("priority", "MEDIUM")
				.param("createFunction", esLintRule.getCreateFunction())
				.param("messages[0].key", esLintRule.getMessages().get(0).getKey())
				.param("messages[0].value", esLintRule.getMessages().get(0).getValue())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("designerView",
						Matchers.nullValue()))
				.andExpect(MockMvcResultMatchers.model().attribute("knownModules",
						Matchers.contains("ESLint")))
				.andExpect(MockMvcResultMatchers.model().attribute("failure",
						Matchers.stringContainsInOrder("Failed to save rule.")));
	}

	@Test
	@WithMockUser(username = "jdoe",
			authorities = {EsLintModule.ESLINT_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveCore() throws Exception {
		String sourceCode = "function foo() {\n\tconsole.log('foo');\n}";
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesigner
				.query(BDDMockito.anyString(), BDDMockito.anyBoolean(), BDDMockito.anyString(),
						BDDMockito.anyString(), BDDMockito.anyList()))
				.thenReturn(mav);
		BDDMockito.when(ruleDesignerService.getKnownModulesForUser(BDDMockito.any()))
				.thenReturn(Arrays.asList("ESLint"));
		mockMvc.perform(MockMvcRequestBuilders.post("/designer/eslint/save")
				.param("sourceCode", sourceCode)
				.param("core", "true")
				.param("name", esLintRule.getName())
				.param("priority", "MEDIUM")
				.param("createFunction", esLintRule.getCreateFunction())
				.param("messages[0].key", esLintRule.getMessages().get(0).getKey())
				.param("messages[0].value", esLintRule.getMessages().get(0).getValue())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("designerView",
						Matchers.nullValue()))
				.andExpect(MockMvcResultMatchers.model().attribute("knownModules",
						Matchers.contains("ESLint")))
				.andExpect(MockMvcResultMatchers.model().attribute("success",
						Matchers.is("Successfully saved rule: rule-name")));

		ArgumentCaptor<EsLintCustomRuleDto> ruleCaptor = ArgumentCaptor.forClass(EsLintCustomRuleDto.class);
		BDDMockito.verify(ruleService).saveRule(ruleCaptor.capture());
		Assertions.assertEquals("jdoe", ruleCaptor.getValue().getAuthor());
	}


	private static EsLintCustomRuleDto getEsLintRuleDto() {
		EsLintCustomRuleDto rule = new EsLintCustomRuleDto();
		rule.setName("rule-name");
		rule.setMessage("This is a bad practice.");
		rule.setExternalUrl("https://example.com");
		rule.setPriority(RulePriority.MEDIUM_HIGH);
		rule.setCore(false);
		EsLintMessageDto message = new EsLintMessageDto();
		message.setKey("myMessage");
		message.setValue("There's something unexpected here");
		rule.setMessages(Collections.singletonList(message));
		rule.setCreateFunction("create(context) {\n"
				+ "\treturn {\n"
				+ "\t\tBinaryExpression(node) {\n"
				+ "\t\t\tconst badOperator = node.operator === \"==\" || node.operator === \"!=\";\n"
				+ "\t\t\tif (node.right.type === \"Literal\" && node.right.raw === \"null\"\n"
				+ "\t\t\t\t\t&& badOperator || node.left.type === \"Literal\"\n"
				+ "\t\t\t\t\t&& node.left.raw === \"null\" && badOperator) {\n"
				+ "\t\t\t\tcontext.report({ node, messageId: \"myMessage\" });\n"
				+ "\t\t\t}\n"
				+ "\t\t}\n"
				+ "\t};\n"
				+ "}");
		return rule;
	}
}
