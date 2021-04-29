package com.tracelink.appsec.module.json.model;

import java.lang.reflect.Field;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.util.ReflectionUtils;

import com.jayway.jsonpath.JsonPath;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class JsonRuleDtoTest {

	@Test
	public void testDAO() {
		String fileExt = "foo";
		String query = "$";
		JsonRuleDto dto = new JsonRuleDto();
		dto.setFileExtension(fileExt);
		dto.setQuery(query);
		Assertions.assertEquals(fileExt, dto.getFileExtension());
		Assertions.assertEquals(query, dto.getQuery());
	}

	@Test
	public void testLazyCompile() {
		String query = "$";
		JsonRuleDto dto = new JsonRuleDto();

		Field compiledField = ReflectionUtils.findField(JsonRuleDto.class, "compiledQuery");
		compiledField.setAccessible(true);
		Assertions.assertNull((JsonPath) ReflectionUtils.getField(compiledField, dto));
		dto.setQuery(query);
		Assertions.assertNull((JsonPath) ReflectionUtils.getField(compiledField, dto));
		JsonPath comp = dto.getCompiledQuery();
		Assertions.assertNotNull((JsonPath) ReflectionUtils.getField(compiledField, dto));
		Assertions.assertEquals(comp, dto.getCompiledQuery());
	}


	@Test
	public void testToEntity() {
		String extUrl = "ext";
		String fileExt = "txt";
		String message = "message";
		String name = "name";
		RulePriority prio = RulePriority.HIGH;
		String query = "$";

		JsonRuleDto rule = new JsonRuleDto();
		rule.setExternalUrl(extUrl);
		rule.setFileExtension(fileExt);
		rule.setMessage(message);
		rule.setName(name);
		rule.setPriority(prio);
		rule.setQuery(query);
		JsonRuleEntity entity = rule.toEntity();
		Assertions.assertEquals(extUrl, entity.getExternalUrl());
		Assertions.assertEquals(fileExt, entity.getFileExtension());
		Assertions.assertEquals(message, entity.getMessage());
		Assertions.assertEquals(name, entity.getName());
		Assertions.assertEquals(prio, entity.getPriority());
		Assertions.assertEquals(query, entity.getQuery());
	}

	@Test
	public void testValidExtension() {
		JsonRuleDto dto = new JsonRuleDto();
		dto.setFileExtension("");
		Assertions.assertTrue(dto.isValidExtension("foobar"));
		Assertions.assertTrue(dto.isValidExtension("foobar.txt"));
		dto.setFileExtension("txt");
		Assertions.assertFalse(dto.isValidExtension("foobar"));
		Assertions.assertTrue(dto.isValidExtension("foobar.txt"));
		Assertions.assertFalse(dto.isValidExtension("foobar.jpg"));
	}
}

