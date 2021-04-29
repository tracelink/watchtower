package com.tracelink.appsec.module.json.interpreter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.json.model.JsonRuleXmlModel;
import com.tracelink.appsec.module.json.model.JsonRulesetXmlModel;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRulesetImpexModel;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractXmlRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Implementation of an {@link AbstractXmlRulesetInterpreter} for importing and exporting rulesets
 * containing Json rules. Uses the {@link JsonRulesetXmlModel} and {@link JsonRuleXmlModel} classes
 * to convert to and from XML.
 *
 * @author csmith
 */
public class JsonRulesetInterpreter extends AbstractXmlRulesetInterpreter {

	@Override
	protected Class<? extends AbstractRulesetImpexModel> getRulesetModelClass() {
		return JsonRulesetXmlModel.class;
	}

	@Override
	protected AbstractRulesetImpexModel fromDto(RulesetDto rulesetDto) {
		JsonRulesetXmlModel ruleset = new JsonRulesetXmlModel();
		ruleset.setName(rulesetDto.getName());
		ruleset.setDescription(rulesetDto.getDescription());
		Set<JsonRuleXmlModel> jsonRules = new HashSet<JsonRuleXmlModel>();
		for (RuleDto ruleDto : rulesetDto.getAllRules()) {
			if (ruleDto instanceof JsonRuleDto) {
				JsonRuleDto jsonRule = (JsonRuleDto) ruleDto;
				JsonRuleXmlModel rule = new JsonRuleXmlModel();
				rule.setName(jsonRule.getName());
				rule.setMessage(jsonRule.getMessage());
				rule.setQuery(jsonRule.getQuery());
				rule.setExtension(jsonRule.getFileExtension());
				rule.setExternalUrl(jsonRule.getExternalUrl());
				rule.setPriority(jsonRule.getPriority().getPriority());
				jsonRules.add(rule);
			}
		}
		// If there are no rules, return null
		if (jsonRules.isEmpty()) {
			return null;
		}
		ruleset.setRules(jsonRules);
		return ruleset;
	}

	@Override
	protected RulesetDto makeExampleRuleset() {
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("Example Json Ruleset");
		ruleset.setDescription("Example Json Ruleset to show necessary model values");

		JsonRuleDto jsonRule = new JsonRuleDto();
		jsonRule.setName("Example Json Rule");
		jsonRule.setMessage("Example Message");
		jsonRule.setQuery("JsonPath Query");
		jsonRule.setFileExtension(".txt");
		jsonRule.setExternalUrl("https://example.com");
		jsonRule.setPriority(RulePriority.HIGH);

		JsonRuleDto jsonRule2 = new JsonRuleDto();
		jsonRule2.setName("Example Json Rule 2");
		jsonRule2.setMessage("Example Message 2");
		jsonRule2.setQuery("JsonPath Query 2");
		jsonRule2.setFileExtension("");
		jsonRule2.setExternalUrl("https://example.com");
		jsonRule2.setPriority(RulePriority.MEDIUM_LOW);

		ruleset.setRules(new HashSet<>(Arrays.asList(jsonRule, jsonRule2)));
		return ruleset;
	}

}
