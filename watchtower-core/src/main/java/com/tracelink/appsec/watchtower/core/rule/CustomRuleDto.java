package com.tracelink.appsec.watchtower.core.rule;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonIgnore;

public abstract class CustomRuleDto extends RuleDto {

	@NotNull(message = "Author" + CANNOT_BE_NULL)
	@NotEmpty(message = "Author" + CANNOT_BE_EMPTY)
	private String author;

	@NotNull(message = "Message" + CANNOT_BE_NULL)
	@NotEmpty(message = "Message" + CANNOT_BE_EMPTY)
	private String message;

	@NotNull(message = "External URL" + CANNOT_BE_NULL)
	@NotEmpty(message = "External URL" + CANNOT_BE_EMPTY)
	@Size(max = 255, message = "External URL cannot have a length of more than 256 characters.")
	private String externalUrl;

	@Override
	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}

	@Override
	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	@Override
	public String getExternalUrl() {
		return externalUrl;
	}

	public void setExternalUrl(String externalUrl) {
		this.externalUrl = externalUrl;
	}

	@Override
	@JsonIgnore
	public final RuleDesignation getRuleDesignation() {
		return RuleDesignation.CUSTOM;
	}
}
