package com.tracelink.appsec.module.pmd.xml;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class PMDRulesetXmlModelTest {

	@Test
	public void testDefaults() {
		PMDRulesetXmlModel pmdRulesetXmlModel = new PMDRulesetXmlModel();
		Assertions.assertEquals("http://pmd.sourceforge.net/ruleset/2.0.0", pmdRulesetXmlModel.getXmlns());
		Assertions.assertEquals("http://www.w3.org/2001/XMLSchema-instance", pmdRulesetXmlModel.getXmlnsXsi());
		Assertions.assertEquals("http://pmd.sourceforge.net/ruleset/2.0.0 https://pmd.sourceforge.io/ruleset_2_0_0.xsd",
				pmdRulesetXmlModel.getXsiSchemaLocation());
	}

	@Test
	public void testGettersAndSetters() {
		PMDRulesetXmlModel pmdRulesetXmlModel = new PMDRulesetXmlModel();
		pmdRulesetXmlModel.setName("Ruleset-Name");
		pmdRulesetXmlModel.setDescription("This is a mock ruleset.");
		PMDRuleXmlModel ruleXmlModel = new PMDRuleXmlModel();
		pmdRulesetXmlModel.setRules(Collections.singleton(ruleXmlModel));
		pmdRulesetXmlModel.setXmlns("https://example.com");
		pmdRulesetXmlModel.setXmlnsXsi("https://foo.com");
		pmdRulesetXmlModel.setXsiSchemaLocation("https://bar.com");
		Assertions.assertEquals("Ruleset-Name", pmdRulesetXmlModel.getName());
		Assertions.assertEquals("This is a mock ruleset.", pmdRulesetXmlModel.getDescription());
		Assertions.assertEquals(ruleXmlModel, pmdRulesetXmlModel.getRules().iterator().next());
		Assertions.assertEquals("https://example.com", pmdRulesetXmlModel.getXmlns());
		Assertions.assertEquals("https://foo.com", pmdRulesetXmlModel.getXmlnsXsi());
		Assertions.assertEquals("https://bar.com", pmdRulesetXmlModel.getXsiSchemaLocation());
	}
}
