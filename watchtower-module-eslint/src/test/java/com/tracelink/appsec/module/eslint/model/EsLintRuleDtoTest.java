package com.tracelink.appsec.module.eslint.model;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class EsLintRuleDtoTest {

	public static EsLintRuleDto getCustomEsLintRule() {
		EsLintRuleDto dto = new EsLintRuleDto();
		dto.setId(1L);
		dto.setAuthor("jdoe");
		dto.setName("eslint-rule");
		dto.setMessage("Some message");
		dto.setExternalUrl("https://example.com");
		dto.setPriority(RulePriority.MEDIUM);
		dto.setCore(false);
		dto.setType(EsLintRuleType.PROBLEM);
		EsLintMessageDto messageDto = new EsLintMessageDto();
		messageDto.setKey("unexpected");
		messageDto.setValue("Some helpful message");
		dto.setMessages(Collections.singletonList(messageDto));
		dto.setCreateFunction("create(context) {\n"
				+ "\treturn {\n"
				+ "\t\tBinaryExpression(node) {\n"
				+ "\t\t\tconst badOperator = node.operator === \"==\" || node.operator === \"!=\";\n"
				+ "\t\t\tif (node.right.type === \"Literal\" && node.right.raw === \"null\"\n"
				+ "\t\t\t\t\t&& badOperator || node.left.type === \"Literal\"\n"
				+ "\t\t\t\t\t&& node.left.raw === \"null\" && badOperator) {\n"
				+ "\t\t\t\tcontext.report({ node, messageId: \"unexpected\" });\n"
				+ "\t\t\t}\n"
				+ "\t\t}\n"
				+ "\t};\n"
				+ "}");
		dto.setCategory("Rule Category");
		dto.setRecommended(false);
		dto.setSuggestion(false);
		dto.setFixable(EsLintRuleFixable.WHITESPACE);
		dto.setSchema("[]");
		dto.setDeprecated(false);
		dto.setReplacedBy("[]");
		return dto;
	}

	@Test
	public void testToEntity() {
		EsLintRuleDto dto = getCustomEsLintRule();
		EsLintRuleEntity rule = (EsLintRuleEntity) dto.toEntity();
		Assertions.assertNotEquals(dto.getId(), rule.getId(), 0.001);
		Assertions.assertNull(rule.getAuthor());
		Assertions.assertEquals(dto.getName(), rule.getName());
		Assertions.assertEquals(dto.getMessage(), rule.getMessage());
		Assertions.assertEquals(dto.getExternalUrl(), rule.getExternalUrl());
		Assertions.assertEquals(dto.getPriority(), rule.getPriority());
		Assertions.assertEquals(dto.isCore(), rule.isCore());
		EsLintMessageDto retMessage = dto.getMessages().get(0);
		EsLintMessageEntity ruleMessage = rule.getMessages().iterator().next();
		Assertions.assertEquals(retMessage.getKey(), ruleMessage.getKey());
		Assertions.assertEquals(retMessage.getValue(), ruleMessage.getValue());
		Assertions.assertEquals(dto.getCreateFunction(), rule.getCreateFunction());
		Assertions.assertEquals(dto.getCategory(), rule.getCategory());
		Assertions.assertEquals(dto.getRecommended(), rule.getRecommended());
		Assertions.assertEquals(dto.getSuggestion(), rule.getSuggestion());
		Assertions.assertEquals(dto.getDeprecated(), rule.getDeprecated());
		Assertions.assertEquals(dto.getReplacedBy(), rule.getReplacedBy());
	}

}
