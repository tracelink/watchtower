package com.tracelink.appsec.module.betterleaks.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.module.betterleaks.engine.BetterleaksRuleTestResult;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleValidator;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleException;

/**
 * Holds imported custom Betterleaks rules to the same bar as the designer: safe fields, and a
 * real-binary test against their samples. Without it a ruleset import could introduce a rule
 * the designer would have refused.
 *
 * @author Watchtower
 */
@Component
public class BetterleaksCustomRuleImportValidator implements CustomRuleValidator {

	private final BetterleaksRuleTester tester;

	public BetterleaksCustomRuleImportValidator(@Autowired BetterleaksRuleTester tester) {
		this.tester = tester;
	}

	@Override
	public boolean supports(RuleDto rule) {
		return rule instanceof BetterleaksCustomRuleDto;
	}

	@Override
	public void validate(RuleDto rule) throws RuleException {
		BetterleaksCustomRuleDto custom = (BetterleaksCustomRuleDto) rule;
		List<String> problems = custom.fieldProblems();
		if (!problems.isEmpty()) {
			throw new RuleException(String.join(" ", problems));
		}
		BetterleaksRuleTestResult result = tester.test(custom);
		if (!result.passed()) {
			throw new RuleException(result.failureReason());
		}
	}
}
