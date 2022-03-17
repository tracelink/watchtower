package com.tracelink.appsec.module.eslint.engine.json;

/**
 * JSON model for the provided rule categories (rulesets) returned by ESLint.
 *
 * @author csmith
 */
public class CategoryDefinition {
	private String name;
	private String description;

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
}
