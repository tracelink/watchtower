package com.tracelink.appsec.module.betterleaks.service;

import org.springframework.stereotype.Component;

import com.tracelink.appsec.module.betterleaks.engine.BetterleaksEngine;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksRuleTestResult;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;

/**
 * Tests custom rules against their samples with the real binary, for the designer, the editor
 * and ruleset imports alike.
 *
 * @author Watchtower
 */
@Component
public class BetterleaksRuleTester {

	private final BetterleaksEngine engine;

	public BetterleaksRuleTester() {
		this(new BetterleaksEngine());
	}

	BetterleaksRuleTester(BetterleaksEngine engine) {
		this.engine = engine;
	}

	/**
	 * @param rule the rule to test
	 * @return how it did against its samples
	 */
	public BetterleaksRuleTestResult test(BetterleaksCustomRuleDto rule) {
		return engine.testRule(rule);
	}
}
