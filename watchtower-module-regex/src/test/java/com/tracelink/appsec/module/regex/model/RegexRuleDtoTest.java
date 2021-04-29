package com.tracelink.appsec.module.regex.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class RegexRuleDtoTest {
	private static Long id = 2L;
	private static String author = "jdoe";
	private static String name = "RegexRule";
	private static String message = "This is a bad practice.";
	private static String externalUrl = "https://example.com";
	private static RulePriority priority = RulePriority.MEDIUM;
	private static String extension = "txt";
	private static String pattern = "AKIA[0-9A-Z]{16}";
	private static RegexRuleDto regexRuleDto = setup();

	public static RegexRuleDto setup() {
		RegexRuleDto regexRuleDto = new RegexRuleDto();
		regexRuleDto.setId(id);
		regexRuleDto.setAuthor(author);
		regexRuleDto.setName(name);
		regexRuleDto.setMessage(message);
		regexRuleDto.setExternalUrl(externalUrl);
		regexRuleDto.setPriority(priority);
		regexRuleDto.setFileExtension(extension);
		regexRuleDto.setRegexPattern(pattern);
		return regexRuleDto;
	}

	@Test
	public void testGetters() {
		Assertions.assertEquals(RegexModule.REGEX_MODULE_NAME, regexRuleDto.getModule());
		Assertions.assertEquals(id, regexRuleDto.getId());
		Assertions.assertEquals(author, regexRuleDto.getAuthor());
		Assertions.assertEquals(name, regexRuleDto.getName());
		Assertions.assertEquals(message, regexRuleDto.getMessage());
		Assertions.assertEquals(externalUrl, regexRuleDto.getExternalUrl());
		Assertions.assertEquals(priority, regexRuleDto.getPriority());
		Assertions.assertEquals(extension, regexRuleDto.getFileExtension());
		Assertions.assertEquals(pattern, regexRuleDto.getRegexPattern());
	}

	@Test
	public void testToEntity() {
		RegexRuleEntity regexRule = (RegexRuleEntity) regexRuleDto.toEntity();
		Assertions.assertEquals(0L, regexRule.getId());
		Assertions.assertNull(regexRule.getAuthor());
		Assertions.assertEquals(name, regexRule.getName());
		Assertions.assertEquals(message, regexRule.getMessage());
		Assertions.assertEquals(externalUrl, regexRule.getExternalUrl());
		Assertions.assertEquals(priority, regexRule.getPriority());
		Assertions.assertEquals(extension, regexRule.getFileExtension());
		Assertions.assertEquals(pattern, regexRule.getRegexPattern());
	}
}
