package com.tracelink.appsec.module.eslint.engine;

/**
 * JSON model for the provided rules returned by the ESLint Linter.
 *
 * @author csmith
 */
public class ProvidedRuleDefinition {
	private String name;
	private String description;
	private String url;
	private String category;

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

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getCategory() {
		return category;
	}

	public void setCategory(String category) {
		this.category = category;
	}
}
