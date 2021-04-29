package com.tracelink.appsec.module.eslint.engine.json;

import java.util.HashMap;
import java.util.Map;

/**
 * JSON model for an ESLint ruleset. Contains a ruleset name and description, a map of custom rule
 * implementations, and a map of rule priorities.
 *
 * @author mcool
 */
public class EsLintRulesetJsonModel {

	private String name;

	private String description;

	private Map<String, EsLintRuleJsonModel> customRules = new HashMap<>();

	private Map<String, Integer> priorities = new HashMap<>();

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public Map<String, EsLintRuleJsonModel> getCustomRules() {
		return customRules;
	}

	public void setCustomRules(Map<String, EsLintRuleJsonModel> customRules) {
		this.customRules = customRules;
	}

	public Map<String, Integer> getPriorities() {
		return priorities;
	}

	public void setPriorities(Map<String, Integer> priorities) {
		this.priorities = priorities;
	}
}
