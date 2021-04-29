package com.tracelink.appsec.watchtower.core.mock;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

public class MockRuleset {

    public static RulesetEntity getDefaultRuleset() {
        RulesetEntity ruleset = new RulesetEntity();
        ruleset.setName("Default");
        ruleset.setDescription("The default set of rules.");
        ruleset.setDesignation(RulesetDesignation.DEFAULT);
        return ruleset;
    }

    public static RulesetEntity getCompositeRuleset() {
        RulesetEntity ruleset = new RulesetEntity();
        ruleset.setName("Composite");
        ruleset.setDescription("Ruleset containing Default rules.");
        ruleset.setDesignation(RulesetDesignation.PRIMARY);
        return ruleset;
    }

    public static RulesetDto getDefaultRulesetDto() {
        RulesetDto dto = getDefaultRuleset().toDto();
        dto.setId(1L);
        return dto;
    }

    public static RulesetDto getCompositeRulesetDto() {
        RulesetDto dto = getCompositeRuleset().toDto();
        dto.setId(2L);
        return dto;
    }
}
