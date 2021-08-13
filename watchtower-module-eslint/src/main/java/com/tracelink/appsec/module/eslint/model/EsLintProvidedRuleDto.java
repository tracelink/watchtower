package com.tracelink.appsec.module.eslint.model;

import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.ProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

/**
 * Represents a data transfer object for the {@link EsLintRuleEntity} for custom rules. All fields
 * in this object are in plain text. Contains ESLint-specific fields and inherits fields from the
 * {@link CustomRuleDto}.
 *
 * @author mcool
 */
public class EsLintProvidedRuleDto extends ProvidedRuleDto implements EsLintRuleDto {
	private String message;
	private String externalUrl;

	public void setMessage(String message) {
		this.message = message;
	}

	@Override
	public String getMessage() {
		return message;
	}

	public void setExternalUrl(String externalUrl) {
		this.externalUrl = externalUrl;
	}

	@Override
	public String getExternalUrl() {
		return externalUrl;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getModule() {
		return EsLintModule.MODULE_NAME;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RuleEntity toEntity() {
		EsLintRuleEntity rule = new EsLintRuleEntity();
		// Set inherited fields
		rule.setName(getName());
		rule.setAuthor(getAuthor());
		rule.setMessage(getMessage());
		rule.setExternalUrl(getExternalUrl());
		rule.setPriority(getPriority());
		// Set ESLint-specific fields
		rule.setCore(isProvided());
		return rule;
	}

}
