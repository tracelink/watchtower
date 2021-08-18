package com.tracelink.appsec.watchtower.core.mock;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

public class MockRuleset {

	public static final String DEFAULT_RULESET_NAME = "Default";
	public static final String DEFAULT_RULESET_DESCRIPTION = "The default set of rules.";
	public static final String COMPOSITE_RULESET_NAME = "Composite";
	public static final String COMPOSITE_RULESET_DESCRIPTION = "Ruleset containing Default rules.";

	public static RulesetEntity getDefaultRuleset() {
		RulesetEntity ruleset = new RulesetEntity();
		ruleset.setName(DEFAULT_RULESET_NAME);
		ruleset.setId(2L);
		ruleset.setDescription(DEFAULT_RULESET_DESCRIPTION);
		ruleset.setDesignation(RulesetDesignation.DEFAULT);
		return ruleset;
	}

	public static RulesetEntity getCompositeRuleset() {
		RulesetEntity ruleset = new RulesetEntity();
		ruleset.setName(COMPOSITE_RULESET_NAME);
		ruleset.setId(1L);
		ruleset.setDescription(COMPOSITE_RULESET_DESCRIPTION);
		ruleset.setDesignation(RulesetDesignation.PRIMARY);
		return ruleset;
	}

	public static RulesetDto getDefaultRulesetDto() {
		RulesetDto dto = getDefaultRuleset().toDto();
		return dto;
	}

	public static RulesetDto getCompositeRulesetDto() {
		RulesetDto dto = getCompositeRuleset().toDto();
		return dto;
	}
}
