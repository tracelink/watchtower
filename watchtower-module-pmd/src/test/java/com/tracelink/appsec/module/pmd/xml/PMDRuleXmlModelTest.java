package com.tracelink.appsec.module.pmd.xml;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class PMDRuleXmlModelTest {
	private String since = "2.0";
	private String name = "PMDRule";
	private String message = "This is a bad practice.";
	private String externalUrl = "https://example.com";
	private RulePriority priority = RulePriority.MEDIUM;
	private String parserLanguage = "java";
	private String ruleClass = "net.sourceforge.pmd.lang.rule.XPathRule";
	private String xpath = "//PrimaryPrefix[Name[starts-with(@Image,\"System.out\")";
	private PMDRuleXmlModel pmdRuleXmlModel;

	@BeforeEach
	public void setup() {
		pmdRuleXmlModel = new PMDRuleXmlModel();
		pmdRuleXmlModel.setName(name);
		pmdRuleXmlModel.setSince(since);
		pmdRuleXmlModel.setLanguage(parserLanguage);
		pmdRuleXmlModel.setMessage(message);
		pmdRuleXmlModel.setClazz(ruleClass);
		pmdRuleXmlModel.setExternalUrl(externalUrl);
		pmdRuleXmlModel.setPriority(priority.getPriority());
		Property property = new Property();
		property.setName("xpath");
		property.setValue(xpath);
		pmdRuleXmlModel.setProperties(Collections.singletonList(property));
		pmdRuleXmlModel.setExample("foo");
	}

	@Test
	public void testToDto() {
		PMDCustomRuleDto pmdRuleDto = (PMDCustomRuleDto) pmdRuleXmlModel.toDto();
		Assertions.assertEquals(PMDModule.PMD_MODULE_NAME, pmdRuleDto.getModule());
		Assertions.assertNull(pmdRuleDto.getId());
		Assertions.assertNull(pmdRuleDto.getAuthor());
		Assertions.assertEquals(name, pmdRuleDto.getName());
		Assertions.assertEquals(message, pmdRuleDto.getMessage());
		Assertions.assertEquals(externalUrl, pmdRuleDto.getExternalUrl());
		Assertions.assertEquals(priority, pmdRuleDto.getPriority());
		Assertions.assertEquals(parserLanguage, pmdRuleDto.getParserLanguage());
		Assertions.assertEquals(ruleClass, pmdRuleDto.getRuleClass());
		Assertions.assertEquals("xpath", pmdRuleDto.getProperties().iterator().next().getName());
		Assertions.assertEquals(xpath, pmdRuleDto.getProperties().iterator().next().getValue());
	}
}
