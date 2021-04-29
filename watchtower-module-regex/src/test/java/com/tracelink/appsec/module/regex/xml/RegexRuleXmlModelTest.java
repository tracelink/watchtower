package com.tracelink.appsec.module.regex.xml;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.module.regex.model.RegexRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class RegexRuleXmlModelTest {
	private String name = "RegexRule";
	private String message = "This is a bad practice.";
	private String externalUrl = "https://example.com";
	private RulePriority priority = RulePriority.MEDIUM;
	private String extension = "txt";
	private String pattern = "AKIA[0-9A-Z]{16}";
	private RegexRuleXmlModel regexRuleXmlModel;

	@BeforeEach
	public void setup() {
		regexRuleXmlModel = new RegexRuleXmlModel();
		regexRuleXmlModel.setName(name);
		regexRuleXmlModel.setMessage(message);
		regexRuleXmlModel.setExtension(extension);
		regexRuleXmlModel.setExternalUrl(externalUrl);
		regexRuleXmlModel.setPriority(priority.getPriority());
		regexRuleXmlModel.setPattern(pattern);
	}

	@Test
	public void testToDto() {
		RegexRuleDto regexRuleDto = (RegexRuleDto) regexRuleXmlModel.toDto();
		Assertions.assertEquals(RegexModule.REGEX_MODULE_NAME, regexRuleDto.getModule());
		Assertions.assertNull(regexRuleDto.getId());
		Assertions.assertNull(regexRuleDto.getAuthor());
		Assertions.assertEquals(name, regexRuleDto.getName());
		Assertions.assertEquals(message, regexRuleDto.getMessage());
		Assertions.assertEquals(externalUrl, regexRuleDto.getExternalUrl());
		Assertions.assertEquals(priority, regexRuleDto.getPriority());
		Assertions.assertEquals(extension, regexRuleDto.getFileExtension());
		Assertions.assertEquals(pattern, regexRuleDto.getRegexPattern());
	}
}
