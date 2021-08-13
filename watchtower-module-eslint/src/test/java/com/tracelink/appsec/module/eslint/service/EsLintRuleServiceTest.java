package com.tracelink.appsec.module.eslint.service;

import java.util.Collections;
import java.util.Optional;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.module.eslint.model.EsLintMessageEntity;
import com.tracelink.appsec.module.eslint.model.EsLintRuleEntity;
import com.tracelink.appsec.module.eslint.repository.EsLintRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditorException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

@ExtendWith(SpringExtension.class)
public class EsLintRuleServiceTest {

	private static final String RULE_NAME = "eslint-rule";

	@MockBean
	private EsLintRuleRepository ruleRepository;

	private static LinterEngine engine;

	private EsLintRuleService ruleService;
	private EsLintRuleEntity rule;

	@BeforeAll
	public static void init() {
		engine = new LinterEngine();
	}

	@BeforeEach
	public void setup() {
		ruleService = new EsLintRuleService(ruleRepository, engine);
		rule = new EsLintRuleEntity();
		rule.setName(RULE_NAME);
	}

	@Test
	public void testGetEsLintRule() {
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));
		Assertions.assertEquals(rule, ruleService.getRule(1L));
	}

	@Test
	public void testGetEsLintRuleNotFound() {
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong())).thenReturn(Optional.empty());
		Assertions.assertNull(ruleService.getRule(1L));
	}

	@Test
	public void testSaveRuleAlreadyExists() {
		BDDMockito.when(ruleRepository.findByName(RULE_NAME))
				.thenReturn(rule);
		EsLintCustomRuleDto dto = new EsLintCustomRuleDto();
		dto.setName(RULE_NAME);
		try {
			ruleService.saveRule(dto);
			Assertions.fail("Should have thrown exception");
		} catch (RuleDesignerException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("An ESLint rule with the given name already exists"));
		}
	}

	@Test
	public void testSaveCoreRuleInvalid() {
		EsLintCustomRuleDto dto = getEsLintRuleDto();
		try {
			ruleService.saveRule(dto);
			Assertions.fail("Should have thrown exception");
		} catch (RuleDesignerException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("\"" + dto.getName()
							+ "\" is not a core rule. Please choose from the provided list"));
		}
	}

	@Test
	public void testSaveCoreRule() throws Exception {
		EsLintCustomRuleDto dto = getEsLintRuleDto();
		dto.setName("no-eq-null");

		ruleService.saveRule(dto);
		ArgumentCaptor<EsLintRuleEntity> entityCaptor = ArgumentCaptor
				.forClass(EsLintRuleEntity.class);
		BDDMockito.verify(ruleRepository).saveAndFlush(entityCaptor.capture());
		EsLintRuleEntity entity = entityCaptor.getValue();
		MatcherAssert.assertThat(entity.getName(), Matchers.is(dto.getName()));
		MatcherAssert.assertThat(entity.isCore(), Matchers.is(dto.isProvided()));
		MatcherAssert.assertThat(entity.getPriority(), Matchers.is(dto.getPriority()));
		MatcherAssert.assertThat(entity.getMessage(), Matchers.not(dto.getMessage()));
		MatcherAssert.assertThat(entity.getExternalUrl(), Matchers.not(dto.getExternalUrl()));
		MatcherAssert.assertThat(entity.getCreateFunction(), Matchers.nullValue());
		MatcherAssert.assertThat(entity.getMessages(), Matchers.empty());
	}

	@Test
	public void testSaveCustomRuleCoreName() {
		EsLintCustomRuleDto dto = getEsLintRuleDto();
		dto.setName("no-eq-null");
		try {
			ruleService.saveRule(dto);
			Assertions.fail("Should have thrown exception");
		} catch (RuleDesignerException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("\"" + dto.getName()
							+ "\" is a core rule. Please provide a different name"));
		}
	}

	@Test
	public void testSaveCustomRuleBlankCreateFunction() {
		EsLintCustomRuleDto dto = getEsLintRuleDto();
		dto.setCreateFunction("");
		try {
			ruleService.saveRule(dto);
			Assertions.fail("Should have thrown exception");
		} catch (RuleDesignerException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("Please provide a create function that is not empty"));
		}
	}

	@Test
	public void testSaveCustomRule() throws Exception {
		EsLintCustomRuleDto dto = getEsLintRuleDto();

		ruleService.saveRule(dto);
		ArgumentCaptor<EsLintRuleEntity> entityCaptor = ArgumentCaptor
				.forClass(EsLintRuleEntity.class);
		BDDMockito.verify(ruleRepository).saveAndFlush(entityCaptor.capture());
		EsLintRuleEntity entity = entityCaptor.getValue();
		MatcherAssert.assertThat(entity.getName(), Matchers.is(dto.getName()));
		MatcherAssert.assertThat(entity.isCore(), Matchers.is(dto.isProvided()));
		MatcherAssert.assertThat(entity.getPriority(), Matchers.is(dto.getPriority()));
		MatcherAssert.assertThat(entity.getMessage(), Matchers.is(dto.getMessage()));
		MatcherAssert.assertThat(entity.getExternalUrl(), Matchers.is(dto.getExternalUrl()));
		MatcherAssert.assertThat(entity.getCreateFunction(), Matchers.is(dto.getCreateFunction()));
		MatcherAssert.assertThat(entity.getMessages(), Matchers.iterableWithSize(1));
		MatcherAssert.assertThat(entity.getMessages().iterator().next().getKey(),
				Matchers.is(dto.getMessages().get(0).getKey()));
		MatcherAssert.assertThat(entity.getMessages().iterator().next().getValue(),
				Matchers.is(dto.getMessages().get(0).getValue()));
	}

	@Test
	public void testEditRuleNotFound() throws Exception {
		Assertions.assertThrows(RuleNotFoundException.class, () -> {
			BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
					.thenReturn(Optional.empty());
			EsLintCustomRuleDto ruleDto = new EsLintCustomRuleDto();
			ruleDto.setId(1L);
			ruleService.editRule(ruleDto);
		});
	}

	@Test
	public void testEditRuleCore() throws Exception {
		rule.setCore(true);
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));

		Long dtoId = 1L;
		String dtoAuthor = "jdoe";
		String dtoName = "eslint-rule-new";
		String dtoMessage = "This is a bad practice.";
		String dtoUrl = "https://example.com";
		RulePriority dtoPriority = RulePriority.MEDIUM_HIGH;

		EsLintCustomRuleDto dto = new EsLintCustomRuleDto();
		dto.setId(dtoId);
		dto.setAuthor(dtoAuthor);
		dto.setName(dtoName);
		dto.setMessage(dtoMessage);
		dto.setExternalUrl(dtoUrl);
		dto.setPriority(dtoPriority);

		ruleService.editRule(dto);
		Assertions.assertEquals(0L, rule.getId());
		Assertions.assertNull(rule.getAuthor());
		Assertions.assertEquals("eslint-rule", rule.getName()); // Name not modified
		Assertions.assertNull(rule.getMessage()); // Message not modified
		Assertions.assertNull(rule.getExternalUrl()); // Url not modified
		Assertions.assertEquals(dtoPriority, rule.getPriority());
		Assertions.assertTrue(rule.isCore()); // Core not modified
	}

	@Test
	public void testEditRuleCustomNoCreate() throws Exception {
		Assertions.assertThrows(RuleEditorException.class, () -> {
			BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
					.thenReturn(Optional.of(rule));
			Long dtoId = 1L;

			EsLintCustomRuleDto dto = new EsLintCustomRuleDto();
			dto.setId(dtoId);

			ruleService.editRule(dto);
		});
	}

	@Test
	public void testEditRuleCustom() throws Exception {
		BDDMockito.when(ruleRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(rule));
		Long dtoId = 1L;
		String dtoAuthor = "jdoe";
		String dtoName = "eslint-rule-new";
		String dtoMessage = "This is a bad practice.";
		String dtoUrl = "https://example.com";
		RulePriority dtoPriority = RulePriority.MEDIUM_HIGH;
		boolean dtoCore = false;
		String dtoMessageKey = "unexpected";
		String dtoMessageValue = "Some helpful message";
		String dtoCreateFunction = "create(context) {\n"
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
				+ "}";

		EsLintMessageEntity messageEntity = new EsLintMessageEntity();
		rule.setMessages(Collections.singleton(messageEntity));

		EsLintCustomRuleDto dto = new EsLintCustomRuleDto();
		dto.setId(dtoId);
		dto.setAuthor(dtoAuthor);
		dto.setName(dtoName);
		dto.setMessage(dtoMessage);
		dto.setExternalUrl(dtoUrl);
		dto.setPriority(dtoPriority);
		EsLintMessageDto message = new EsLintMessageDto();
		message.setId(0L);
		message.setKey(dtoMessageKey);
		message.setValue(dtoMessageValue);
		dto.setMessages(Collections.singletonList(message));
		dto.setCreateFunction(dtoCreateFunction);

		ruleService.editRule(dto);
		Assertions.assertEquals(0L, rule.getId());
		Assertions.assertNull(rule.getAuthor());
		Assertions.assertEquals(dtoName, rule.getName());
		Assertions.assertEquals(dtoMessage, rule.getMessage());
		Assertions.assertEquals(dtoUrl, rule.getExternalUrl());
		Assertions.assertEquals(dtoPriority, rule.getPriority());
		Assertions.assertEquals(dtoCore, rule.isCore());
		Assertions.assertEquals(dtoMessageKey, messageEntity.getKey());
		Assertions.assertEquals(dtoMessageValue, messageEntity.getValue());
		Assertions.assertEquals(dtoCreateFunction, rule.getCreateFunction());
	}

	private static EsLintCustomRuleDto getEsLintRuleDto() {
		EsLintCustomRuleDto rule = new EsLintCustomRuleDto();
		rule.setAuthor("jdoe");
		rule.setName("rule-name");
		rule.setMessage("This is a bad practice.");
		rule.setExternalUrl("https://example.com");
		rule.setPriority(RulePriority.MEDIUM_HIGH);
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
