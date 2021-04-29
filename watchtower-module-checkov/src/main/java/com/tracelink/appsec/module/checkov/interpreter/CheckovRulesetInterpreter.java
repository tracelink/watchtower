package com.tracelink.appsec.module.checkov.interpreter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.util.Strings;

import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.module.checkov.model.CheckovRuleDto;
import com.tracelink.appsec.watchtower.core.module.interpreter.RulesetInterpreterException;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractJsonRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRulesetImpexModel;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Implementation of an {@link AbstractJsonRulesetInterpreter} for importing and exporting rulesets
 * containing Checkov rules. Uses the {@link CheckovRulesetJsonModel} and
 * {@link AbstractCheckovRuleModel} classes to convert to and from JSON.
 *
 * @author csmith
 */
public class CheckovRulesetInterpreter extends AbstractJsonRulesetInterpreter {
	private final CheckovEngine engine;

	public CheckovRulesetInterpreter(CheckovEngine engine) {
		this.engine = engine;
	}

	@Override
	protected Class<? extends AbstractRulesetImpexModel> getRulesetModelClass() {
		return CheckovRulesetJsonModel.class;
	}

	@Override
	protected RulesetDto importInternal(AbstractRulesetImpexModel impexModel)
			throws RulesetInterpreterException {
		RulesetDto ruleset = super.importInternal(impexModel);
		Set<String> ruleNames = new HashSet<>();
		Set<String> duplicates =
				ruleset.getAllRules().stream().map(RuleDto::getName).filter(i -> !ruleNames.add(i))
						.collect(Collectors.toSet());
		if (!duplicates.isEmpty()) {
			throw new RulesetInterpreterException(
					"Duplicate Rules Detected. There are multiple instances of the following rule(s): "
							+ String.join(",", duplicates));
		}
		Map<String, CheckovRuleDto> coreRules = engine.getCoreRules();
		List<String> nonCoreRules = ruleset.getAllRules().stream().map(RuleDto::getName)
				.filter(r -> !coreRules.containsKey(r)).collect(Collectors.toList());
		if (!nonCoreRules.isEmpty()) {
			throw new RulesetInterpreterException("The following rules are not Checkov Core Rules: "
					+ Strings.join(nonCoreRules, ','));
		}
		// handle adding core rule data into imported rule
		ruleset.getAllRules().stream().filter(r -> coreRules.containsKey(r.getName()))
				.forEach(r -> {
					CheckovRuleDto newRule = (CheckovRuleDto) r;
					CheckovRuleDto coreRule = coreRules.get(r.getName());
					newRule.setAuthor(coreRule.getAuthor());
					newRule.setCheckovType(coreRule.getCheckovType());
					newRule.setCheckovEntity(coreRule.getCheckovEntity());
					newRule.setMessage(coreRule.getMessage());
					newRule.setCheckovIac(coreRule.getCheckovIac());
					newRule.setExternalUrl(coreRule.getExternalUrl());
					newRule.setCoreRule(coreRule.isCoreRule());
				});
		return ruleset;
	}

	@Override
	protected AbstractRulesetImpexModel fromDto(RulesetDto rulesetDto) {
		CheckovRulesetJsonModel ruleset = new CheckovRulesetJsonModel();
		ruleset.setName(rulesetDto.getName());
		ruleset.setDescription(ruleset.getDescription());
		rulesetDto.getRules().stream().filter(r -> r instanceof CheckovRuleDto)
				.map(r -> (CheckovRuleDto) r).forEach(r -> {
					if (r.isCoreRule()) {
						CheckovCoreRuleModel coreRule = new CheckovCoreRuleModel();
						coreRule.setCoreRuleName(r.getName());
						coreRule.setPriority(r.getPriority().getPriority());
						ruleset.getRules().add(coreRule);
					}
				});
		return ruleset;
	}

	@Override
	protected RulesetDto makeExampleRuleset() {
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("Example Checkov Ruleset");
		ruleset.setDescription(
				"Example Checkov Ruleset Description. Core Rules have a name related to a rule known to Checkov and priority for Watchtower");
		CheckovRuleDto rule = new CheckovRuleDto();
		rule.setCoreRule(true);
		rule.setName("CKV_AWS_1");
		rule.setPriority(RulePriority.HIGH);
		ruleset.setRules(new LinkedHashSet<>(Arrays.asList(rule)));
		return ruleset;
	}

}
