package com.tracelink.appsec.module.checkov.interpreter;

import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRulesetImpexModel;

/**
 * Basic model for a Checkov Ruleset. Only requires name, description, and list of rules
 * 
 * @author csmith
 *
 */
public class CheckovRulesetJsonModel extends AbstractRulesetImpexModel {

	@JsonProperty("name")
	private String rulesetName;

	@JsonProperty("description")
	private String rulesetDescription;

	@JsonProperty("rules")
	private Set<AbstractCheckovRuleModel> rules = new HashSet<>();

	@Override
	public String getName() {
		return rulesetName;
	}

	public void setName(String rulesetName) {
		this.rulesetName = rulesetName;
	}

	@Override
	public String getDescription() {
		return rulesetDescription;
	}

	public void setDescription(String rulesetDescription) {
		this.rulesetDescription = rulesetDescription;
	}

	@Override
	public Set<AbstractCheckovRuleModel> getRules() {
		return rules;
	}
}
