package com.tracelink.appsec.module.eslint.model;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class EsLintRuleDtoTest {

	public static EsLintCustomRuleDto getCustomEsLintRule() {
		EsLintCustomRuleDto dto = new EsLintCustomRuleDto();
		dto.setId(1L);
		dto.setAuthor("jdoe");
		dto.setName("my-no-eq-null");
		dto.setMessage("Some message");
		dto.setExternalUrl("https://example.com");
		dto.setPriority(RulePriority.MEDIUM);
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
		dto.setSchema("[]");
		return dto;
	}

	@Test
	public void testToEntity() {
		EsLintCustomRuleDto dto = getCustomEsLintRule();
		EsLintRuleEntity rule = (EsLintRuleEntity) dto.toEntity();
		Assertions.assertNotEquals(dto.getId(), rule.getId(), 0.001);
		Assertions.assertEquals(dto.getAuthor(), rule.getAuthor());
		Assertions.assertEquals(dto.getName(), rule.getName());
		Assertions.assertEquals(dto.getMessage(), rule.getMessage());
		Assertions.assertEquals(dto.getExternalUrl(), rule.getExternalUrl());
		Assertions.assertEquals(dto.getPriority(), rule.getPriority());
		Assertions.assertEquals(dto.isProvided(), rule.isCore());
		EsLintMessageDto retMessage = dto.getMessages().get(0);
		EsLintMessageEntity ruleMessage = rule.getMessages().iterator().next();
		Assertions.assertEquals(retMessage.getKey(), ruleMessage.getKey());
		Assertions.assertEquals(retMessage.getValue(), ruleMessage.getValue());
		Assertions.assertEquals(dto.getCreateFunction(), rule.getCreateFunction());
	}

}
