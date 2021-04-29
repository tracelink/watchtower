package com.tracelink.appsec.module.json.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class JsonRuleEntityTest {

	@Test
	public void testDAO() {
		String fileExt = "foo";
		String query = "$";
		JsonRuleEntity entity = new JsonRuleEntity();
		entity.setFileExtension(fileExt);
		entity.setQuery(query);
		Assertions.assertEquals(fileExt, entity.getFileExtension());
		Assertions.assertEquals(query, entity.getQuery());
	}

	@Test
	public void testToDto() {
		String author = "author";
		String extUrl = "ext";
		String fileExt = "txt";
		String message = "message";
		String name = "name";
		RulePriority priority = RulePriority.HIGH;
		String query = "$";

		JsonRuleEntity rule = new JsonRuleEntity();
		rule.setExternalUrl(extUrl);
		rule.setFileExtension(fileExt);
		rule.setMessage(message);
		rule.setName(name);
		rule.setPriority(priority);
		rule.setQuery(query);
		rule.setAuthor(author);

		JsonRuleDto dto = rule.toDto();
		Assertions.assertEquals(extUrl, dto.getExternalUrl());
		Assertions.assertEquals(fileExt, dto.getFileExtension());
		Assertions.assertEquals(message, dto.getMessage());
		Assertions.assertEquals(name, dto.getName());
		Assertions.assertEquals(priority, dto.getPriority());
		Assertions.assertEquals(query, dto.getQuery());
		Assertions.assertEquals(author, dto.getAuthor());
	}
}
