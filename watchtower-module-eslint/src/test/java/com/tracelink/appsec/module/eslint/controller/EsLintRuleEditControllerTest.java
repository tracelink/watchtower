package com.tracelink.appsec.module.eslint.controller;

import java.io.FileInputStream;
import java.nio.file.Paths;
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
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockMultipartFile;
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

import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintMessageEntity;
import com.tracelink.appsec.module.eslint.model.EsLintRuleEntity;
import com.tracelink.appsec.module.eslint.service.EsLintRuleService;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleEditController;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetRepository;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class EsLintRuleEditControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private RuleEditController ruleEditController;

	@MockBean
	private RuleService ruleService;

	@MockBean
	private EsLintRuleService esLintRuleService;

	@MockBean
	private UserService userService;

	@MockBean
	private RulesetRepository rulesetRepository;

	@MockBean
	private RuleRepository ruleRepository;

	@Autowired
	private EsLintRuleEditController esLintRuleEditController;

	private EsLintCustomRuleDto esLintRule;

	@BeforeEach
	public void setup() {
		esLintRule = getEsLintRuleDto();
	}

	@Test
	@WithMockUser(authorities = {EsLintModule.ESLINT_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditEsLintRule() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/eslint")
				.param("id", esLintRule.getId().toString())
				.param("author", esLintRule.getAuthor())
				.param("name", "new-name")
				.param("message", esLintRule.getMessage())
				.param("externalUrl", esLintRule.getExternalUrl())
				.param("priority", esLintRule.getPriority().toString())
				.param("core", Boolean.toString(esLintRule.isCore()))
				.param("createFunction", esLintRule.getCreateFunction())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully edited rule."));
		ArgumentCaptor<EsLintCustomRuleDto> argumentCaptor =
				ArgumentCaptor.forClass(EsLintCustomRuleDto.class);
		BDDMockito.verify(esLintRuleService).editRule(argumentCaptor.capture());
		Assertions.assertEquals("new-name", argumentCaptor.getValue().getName());
	}

	@Test
	@WithMockUser(authorities = {EsLintModule.ESLINT_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditEsLintRuleNotFound() throws Exception {
		BDDMockito.doThrow(RuleNotFoundException.class).when(esLintRuleService)
				.editRule(BDDMockito.any(EsLintCustomRuleDto.class));
		mockMvc.perform(MockMvcRequestBuilders.post("/rule/edit/eslint")
				.param("id", esLintRule.getId().toString())
				.param("author", esLintRule.getAuthor()).param("name", "new-name")
				.param("message", esLintRule.getMessage())
				.param("externalUrl", esLintRule.getExternalUrl())
				.param("priority", esLintRule.getPriority().toString())
				.param("core", Boolean.toString(esLintRule.isCore()))
				.param("createFunction", esLintRule.getCreateFunction())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot edit rule.")));
	}

	@Test
	@WithMockUser(authorities = {EsLintModule.ESLINT_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditEsLintRuleValidateFailure() {
		String defaultMessage = "message";
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		BDDMockito.when(bindingResult.hasErrors()).thenReturn(true);
		BDDMockito.when(bindingResult.getFieldErrors())
				.thenReturn(Arrays.asList(new FieldError("", "", defaultMessage)));
		EsLintCustomRuleDto rule = getEsLintRuleDto();
		RedirectAttributes redirect = new RedirectAttributesModelMap();
		Assertions.assertEquals("redirect:/rule/edit/eslint/" + rule.getId(),
				esLintRuleEditController.editRule(rule, bindingResult, redirect));
		MatcherAssert.assertThat(String.valueOf(
				redirect.getFlashAttributes().get(WatchtowerModelAndView.FAILURE_NOTIFICATION)),
				Matchers.containsString("Cannot edit rule"));
	}

	@Test
	@WithMockUser(authorities = {EsLintModule.ESLINT_RULE_EDIT_PRIVILEGE_NAME})
	public void testEditEsLintRuleValidateFailureNameClash() {
		BDDMockito.when(
				ruleService.createsNameCollision(BDDMockito.anyLong(), BDDMockito.anyString()))
				.thenReturn(true);
		BindingResult bindingResult = BDDMockito.mock(BindingResult.class);
		EsLintCustomRuleDto rule = getEsLintRuleDto();
		Assertions.assertEquals("redirect:/rule/edit/eslint/" + rule.getId(),
				esLintRuleEditController.editRule(rule, bindingResult,
						new RedirectAttributesModelMap()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULESETS_MODIFY_NAME})
	public void testImportEsLintRuleset() throws Exception {
		UserEntity user = new UserEntity();
		BDDMockito.when(userService.findByUsername(BDDMockito.anyString())).thenReturn(user);
		MockMultipartFile file = new MockMultipartFile("file",
				new FileInputStream(
						Paths.get(getClass().getResource("/import/ruleset.js").toURI())
								.toFile()));
		mockMvc.perform(MockMvcRequestBuilders.multipart("/rulesets/import").file(file)
				.param("ruleType", "eslint")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully imported ruleset."));

		ArgumentCaptor<RulesetEntity> rulesetCaptor = ArgumentCaptor.forClass(RulesetEntity.class);
		BDDMockito.verify(rulesetRepository, Mockito.times(2))
				.saveAndFlush(rulesetCaptor.capture());
		RulesetEntity ruleset = rulesetCaptor.getAllValues().get(1);
		Assertions.assertEquals("ESLint Rules", ruleset.getName());
		Assertions.assertEquals("A collection of custom and core ESLint rules",
				ruleset.getDescription());
	}

	public static EsLintRuleEntity getEsLintRule() {
		EsLintRuleEntity rule = new EsLintRuleEntity();
		rule.setAuthor("jdoe");
		rule.setName("rule-name");
		rule.setMessage("This is a bad practice.");
		rule.setExternalUrl("https://example.com");
		rule.setPriority(RulePriority.MEDIUM_HIGH);
		rule.setCore(false);
		EsLintMessageEntity message = new EsLintMessageEntity();
		message.setKey("unexpected");
		message.setValue("There's something unexpected here");
		rule.setMessages(Collections.singleton(message));
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

	public static EsLintCustomRuleDto getEsLintRuleDto() {
		EsLintCustomRuleDto dto = (EsLintCustomRuleDto) getEsLintRule().toDto();
		dto.setId(1L);
		return dto;
	}
}
