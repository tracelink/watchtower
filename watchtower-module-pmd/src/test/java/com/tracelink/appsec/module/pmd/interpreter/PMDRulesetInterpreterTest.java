package com.tracelink.appsec.module.pmd.interpreter;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.pmd.model.PMDRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDRuleDtoTest;
import com.tracelink.appsec.module.pmd.xml.PMDRuleXmlModel;
import com.tracelink.appsec.module.pmd.xml.PMDRulesetXmlModel;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRulesetImpexModel;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

public class PMDRulesetInterpreterTest {

	@Test
	public void testGetXmlModelClass() {
		Assertions.assertEquals(PMDRulesetXmlModel.class,
				new PMDRulesetInterpreter().getRulesetModelClass());
	}

	@Test
	public void testFromDto() {
		RulesetDto rulesetDto = new RulesetDto();
		rulesetDto.setName("Mock Ruleset");
		rulesetDto.setDescription("Ruleset containing mock rules");
		PMDRuleDto ruleDto = PMDRuleDtoTest.setup();
		rulesetDto.setRules(Collections.singleton(ruleDto));

		AbstractRulesetImpexModel rulesetXmlModel = new PMDRulesetInterpreter().fromDto(rulesetDto);
		Assertions.assertEquals("Mock Ruleset", rulesetXmlModel.getName());
		Assertions.assertEquals("Ruleset containing mock rules", rulesetXmlModel.getDescription());
		Assertions.assertFalse(rulesetXmlModel.getRules().isEmpty());
		PMDRuleXmlModel ruleXmlModel =
				(PMDRuleXmlModel) rulesetXmlModel.getRules().iterator().next();
		Assertions.assertEquals(ruleDto.getName(), ruleXmlModel.getName());
		Assertions.assertEquals(ruleDto.getMessage(), ruleXmlModel.getMessage());
		Assertions.assertEquals(ruleDto.getExternalUrl(), ruleXmlModel.getExternalUrl());
		Assertions.assertEquals(ruleDto.getPriority().getPriority(), ruleXmlModel.getPriority());
		Assertions.assertEquals(ruleDto.getParserLanguage(), ruleXmlModel.getLanguage());
		Assertions.assertEquals(ruleDto.getRuleClass(), ruleXmlModel.getClazz());
		Assertions.assertEquals(ruleDto.getDescription(), ruleXmlModel.getDescription());
		Assertions.assertEquals("xpath", ruleXmlModel.getProperties().get(0).getName());
		Assertions.assertEquals(ruleDto.getProperties().iterator().next().getValue(),
				ruleXmlModel.getProperties().get(0).getValue());
		Assertions.assertEquals("1.0", ruleXmlModel.getSince());
		Assertions.assertEquals("", ruleXmlModel.getExample());
	}

	@Test
	public void testFromDtoNoRulesMatch() {
		RulesetDto rulesetDto = new RulesetDto();
		rulesetDto.setName("Mock Ruleset");
		rulesetDto.setDescription("Ruleset containing mock rules");

		Assertions.assertNull(new PMDRulesetInterpreter().fromDto(rulesetDto));
	}
}
