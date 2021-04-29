package com.tracelink.appsec.module.pmd.interpreter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.module.pmd.model.PMDRuleDto;
import com.tracelink.appsec.module.pmd.xml.PMDRuleXmlModel;
import com.tracelink.appsec.module.pmd.xml.PMDRulesetXmlModel;
import com.tracelink.appsec.module.pmd.xml.Property;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRulesetImpexModel;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractXmlRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Implementation of an {@link AbstractXmlRulesetInterpreter} for importing and exporting rulesets
 * containing PMD rules. Uses the {@link PMDRulesetXmlModel} and {@link PMDRuleXmlModel} classes to
 * convert to and from XML.
 *
 * @author mcool
 */
public class PMDRulesetInterpreter extends AbstractXmlRulesetInterpreter {
	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Class<? extends AbstractRulesetImpexModel> getRulesetModelClass() {
		return PMDRulesetXmlModel.class;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected AbstractRulesetImpexModel fromDto(RulesetDto rulesetDto) {
		PMDRulesetXmlModel rulesetXmlModel = new PMDRulesetXmlModel();
		rulesetXmlModel.setName(rulesetDto.getName());
		rulesetXmlModel.setDescription(rulesetDto.getDescription());
		Set<PMDRuleXmlModel> ruleXmlModels = new HashSet<>();
		for (RuleDto ruleDto : rulesetDto.getAllRules()) {
			if (ruleDto instanceof PMDRuleDto) {
				PMDRuleXmlModel ruleXmlModel = fromDto((PMDRuleDto) ruleDto);
				ruleXmlModels.add(ruleXmlModel);
			}
		}
		// If there are no rules, return null
		if (ruleXmlModels.isEmpty()) {
			return null;
		}

		rulesetXmlModel.setRules(ruleXmlModels);
		return rulesetXmlModel;
	}

	private PMDRuleXmlModel fromDto(PMDRuleDto dto) {
		PMDRuleXmlModel xmlModel = new PMDRuleXmlModel();
		xmlModel.setName(dto.getName());
		xmlModel.setLanguage(dto.getParserLanguage());
		xmlModel.setMessage(dto.getMessage());
		xmlModel.setClazz(dto.getRuleClass());
		xmlModel.setExternalUrl(dto.getExternalUrl());
		xmlModel.setDescription(dto.getDescription());
		xmlModel.setPriority(dto.getPriority().getPriority());
		// Set all properties
		List<Property> properties = new ArrayList<>();
		for (PMDPropertyDto pmdProperty : dto.getProperties()) {
			Property property = new Property();
			property.setName(pmdProperty.getName());
			property.setValue(pmdProperty.getValue());
			properties.add(property);
		}
		xmlModel.setProperties(properties);
		return xmlModel;
	}

	@Override
	protected RulesetDto makeExampleRuleset() {
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("Example PMD Ruleset");
		ruleset.setDescription("Example PMD Ruleset to show necessary model values");

		PMDRuleDto pmdRule = new PMDRuleDto();
		pmdRule.setName("Example Json Rule");
		pmdRule.setParserLanguage("Java");
		pmdRule.setMessage("Example Message");
		pmdRule.setRuleClass("net.sourceforge.pmd.lang.rule.XPathRule");
		pmdRule.setExternalUrl("https://example.com");
		pmdRule.setDescription("An Example PMD Rule, using XPath and properties");
		pmdRule.setPriority(RulePriority.HIGH);

		PMDPropertyDto property = new PMDPropertyDto();
		property.setName("xpath");
		property.setValue("XPath Query");
		pmdRule.setProperties(Arrays.asList(property));

		PMDRuleDto pmdRule2 = new PMDRuleDto();
		pmdRule2.setName("Example Json Rule");
		pmdRule2.setParserLanguage("Java");
		pmdRule2.setMessage("Example Message");
		pmdRule2.setRuleClass("com.my.custom.Rule");
		pmdRule2.setExternalUrl("https://example.com");
		pmdRule2.setDescription("An Example PMD Rule, using a class");
		pmdRule2.setPriority(RulePriority.HIGH);

		ruleset.setRules(new HashSet<>(Arrays.asList(pmdRule, pmdRule2)));
		return ruleset;
	}
}
