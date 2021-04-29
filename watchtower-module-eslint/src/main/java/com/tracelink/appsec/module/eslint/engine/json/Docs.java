package com.tracelink.appsec.module.eslint.engine.json;

/**
 * JSON model for the "docs" section of ESLint rule metadata.
 *
 * @author mcool
 */
public class Docs {

	private String description;

	private String category;

	private Boolean recommended;

	private String url;

	private Boolean suggestion;

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getCategory() {
		return category;
	}

	public void setCategory(String category) {
		this.category = category;
	}

	public Boolean getRecommended() {
		return recommended;
	}

	public void setRecommended(Boolean recommended) {
		this.recommended = recommended;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public Boolean getSuggestion() {
		return suggestion;
	}

	public void setSuggestion(Boolean suggestion) {
		this.suggestion = suggestion;
	}
}
