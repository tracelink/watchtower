package com.tracelink.appsec.module.pmd.model;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class PMDRuleDtoTest {
	private static Long id = 2L;
	private static String author = "jdoe";
	private static String name = "PMDRule";
	private static String message = "This is a bad practice.";
	private static String externalUrl = "https://example.com";
	private static RulePriority priority = RulePriority.MEDIUM;
	private static String parserLanguage = "java";
	private static String ruleClass = "net.sourceforge.pmd.lang.rule.XPathRule";
	private static String description = "This is a bad practice.";
	private static String xpath = "//PrimaryPrefix[Name[starts-with(@Image,\"System.out\")";
	private PMDRuleDto pmdRuleDto = setup();

	public static PMDRuleDto setup() {
		PMDRuleDto pmdRuleDto = new PMDRuleDto();
		pmdRuleDto.setId(id);
		pmdRuleDto.setAuthor(author);
		pmdRuleDto.setName(name);
		pmdRuleDto.setMessage(message);
		pmdRuleDto.setExternalUrl(externalUrl);
		pmdRuleDto.setPriority(priority);
		pmdRuleDto.setParserLanguage(parserLanguage);
		pmdRuleDto.setRuleClass(ruleClass);
		pmdRuleDto.setDescription(description);
		PMDPropertyDto property = new PMDPropertyDto();
		property.setName("xpath");
		property.setValue(xpath);
		pmdRuleDto.setProperties(Collections.singletonList(property));
		return pmdRuleDto;
	}

	@Test
	public void testGetters() {
		Assertions.assertEquals(PMDModule.PMD_MODULE_NAME, pmdRuleDto.getModule());
		Assertions.assertEquals(id, pmdRuleDto.getId());
		Assertions.assertEquals(author, pmdRuleDto.getAuthor());
		Assertions.assertEquals(name, pmdRuleDto.getName());
		Assertions.assertEquals(message, pmdRuleDto.getMessage());
		Assertions.assertEquals(externalUrl, pmdRuleDto.getExternalUrl());
		Assertions.assertEquals(priority, pmdRuleDto.getPriority());
		Assertions.assertEquals(parserLanguage, pmdRuleDto.getParserLanguage());
		Assertions.assertEquals(ruleClass, pmdRuleDto.getRuleClass());
		Assertions.assertEquals(description, pmdRuleDto.getDescription());
		Assertions.assertEquals("xpath", pmdRuleDto.getProperties().iterator().next().getName());
		Assertions.assertEquals(xpath, pmdRuleDto.getProperties().iterator().next().getValue());
	}

	@Test
	public void testToEntity() {
		PMDRuleEntity pmdRule = (PMDRuleEntity) pmdRuleDto.toEntity();
		Assertions.assertEquals(0L, pmdRule.getId());
		Assertions.assertNull(pmdRule.getAuthor());
		Assertions.assertEquals(name, pmdRule.getName());
		Assertions.assertEquals(message, pmdRule.getMessage());
		Assertions.assertEquals(externalUrl, pmdRule.getExternalUrl());
		Assertions.assertEquals(priority, pmdRule.getPriority());
		Assertions.assertEquals(parserLanguage, pmdRule.getParserLanguage());
		Assertions.assertEquals(ruleClass, pmdRule.getRuleClass());
		Assertions.assertEquals(description, pmdRule.getDescription());
		Assertions.assertEquals("xpath", pmdRule.getProperties().iterator().next().getName());
		Assertions.assertEquals(xpath, pmdRule.getProperties().iterator().next().getValue());
	}
}
