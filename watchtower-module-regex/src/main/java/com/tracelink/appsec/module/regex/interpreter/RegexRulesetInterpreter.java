package com.tracelink.appsec.module.regex.interpreter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.tracelink.appsec.module.regex.model.RegexRuleDto;
import com.tracelink.appsec.module.regex.xml.RegexRuleXmlModel;
import com.tracelink.appsec.module.regex.xml.RegexRulesetXmlModel;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRulesetImpexModel;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractXmlRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Implementation of an {@link AbstractXmlRulesetInterpreter} for importing and exporting rulesets
 * containing Regex rules. Uses the {@link RegexRulesetXmlModel} and {@link RegexRuleXmlModel}
 * classes to convert to and from XML.
 *
 * @author mcool
 */
public class RegexRulesetInterpreter extends AbstractXmlRulesetInterpreter {
	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Class<? extends AbstractRulesetImpexModel> getRulesetModelClass() {
		return RegexRulesetXmlModel.class;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected AbstractRulesetImpexModel fromDto(RulesetDto rulesetDto) {
		RegexRulesetXmlModel rulesetXmlModel = new RegexRulesetXmlModel();
		rulesetXmlModel.setName(rulesetDto.getName());
		rulesetXmlModel.setDescription(rulesetDto.getDescription());
		Set<RegexRuleXmlModel> ruleXmlModels = new HashSet<>();
		for (RuleDto ruleDto : rulesetDto.getAllRules()) {
			if (ruleDto instanceof RegexRuleDto) {
				RegexRuleDto regexRuleDto = (RegexRuleDto) ruleDto;
				// Create XML model object with DTO fields
				RegexRuleXmlModel ruleXmlModel = new RegexRuleXmlModel();
				ruleXmlModel.setName(regexRuleDto.getName());
				ruleXmlModel.setMessage(regexRuleDto.getMessage());
				ruleXmlModel.setExtension(regexRuleDto.getFileExtension());
				ruleXmlModel.setPattern(regexRuleDto.getRegexPattern());
				ruleXmlModel.setExternalUrl(regexRuleDto.getExternalUrl());
				ruleXmlModel.setPriority(regexRuleDto.getPriority().getPriority());
				// Add XML model to the set
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

	@Override
	protected RulesetDto makeExampleRuleset() {
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("Example Regex Ruleset");
		ruleset.setDescription("Example Regex Ruleset to show necessary model values");

		RegexRuleDto regexRule = new RegexRuleDto();
		regexRule.setName("Example Json Rule");
		regexRule.setMessage("Example Message");
		regexRule.setFileExtension("txt");
		regexRule.setRegexPattern("A Regular Expression");
		regexRule.setExternalUrl("https://example.com");
		regexRule.setPriority(RulePriority.HIGH);

		RegexRuleDto regexRule2 = new RegexRuleDto();
		regexRule2.setName("Example Json Rule");
		regexRule2.setMessage(
				"Example Message. This Rule uses a blank extension, matching all files");
		regexRule2.setFileExtension("");
		regexRule2.setRegexPattern("A Regular Expression");
		regexRule2.setExternalUrl("https://example.com");
		regexRule2.setPriority(RulePriority.MEDIUM);

		ruleset.setRules(new HashSet<>(Arrays.asList(regexRule, regexRule2)));
		return ruleset;
	}
}
