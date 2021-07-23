package com.tracelink.appsec.module.eslint.model;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.validation.Valid;
import javax.validation.constraints.Size;

import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

/**
 * Represents a data transfer object for the {@link EsLintRuleEntity}. All fields in this object are
 * in plain text. Contains ESLint-specific fields and inherits fields from the {@link RuleDto}.
 *
 * @author mcool
 */
public class EsLintRuleDto extends CustomRuleDto {

	private boolean core = false;

	@Valid
	private List<EsLintMessageDto> messages = new ArrayList<>();

	private String createFunction;

	/*
	 * OPTIONAL FIELDS The remaining fields are included in the ESLint rule model, but are not
	 * useful for Watchtower. They are included here to support compatibility with preexisting rules
	 * so that we do not lose any information on ruleset import/export.
	 */

	private EsLintRuleType type;

	@Size(max = 255, message = "Category cannot have a length of more than 256 characters.")
	private String category;

	private Boolean recommended;

	private Boolean suggestion;

	private EsLintRuleFixable fixable;

	private String schema;

	private Boolean deprecated;

	private String replacedBy;

	/*
	 * END OPTIONAL FIELDS
	 */

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getModule() {
		return EsLintModule.MODULE_NAME;
	}

	public boolean isCore() {
		return core;
	}

	public void setCore(boolean core) {
		this.core = core;
	}

	public List<EsLintMessageDto> getMessages() {
		return messages;
	}

	public void setMessages(List<EsLintMessageDto> messages) {
		this.messages = messages;
	}

	public String getCreateFunction() {
		return createFunction;
	}

	public void setCreateFunction(String createFunction) {
		this.createFunction = createFunction;
	}

	public EsLintRuleType getType() {
		return type;
	}

	public void setType(EsLintRuleType type) {
		this.type = type;
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

	public Boolean getSuggestion() {
		return suggestion;
	}

	public void setSuggestion(Boolean suggestion) {
		this.suggestion = suggestion;
	}

	public EsLintRuleFixable getFixable() {
		return fixable;
	}

	public void setFixable(EsLintRuleFixable fixable) {
		this.fixable = fixable;
	}

	public String getSchema() {
		return schema;
	}

	public void setSchema(String schema) {
		this.schema = schema;
	}

	public Boolean getDeprecated() {
		return deprecated;
	}

	public void setDeprecated(Boolean deprecated) {
		this.deprecated = deprecated;
	}

	public String getReplacedBy() {
		return replacedBy;
	}

	public void setReplacedBy(String replacedBy) {
		this.replacedBy = replacedBy;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RuleEntity toEntity() {
		EsLintRuleEntity rule = new EsLintRuleEntity();
		// Set inherited fields
		rule.setName(getName());
		rule.setMessage(getMessage());
		rule.setExternalUrl(getExternalUrl());
		rule.setPriority(getPriority());
		// Set ESLint-specific fields
		rule.setCore(isCore());
		rule.setMessages(
				getMessages().stream().map(EsLintMessageDto::toEntity)
						.collect(Collectors.toSet()));
		rule.setCreateFunction(getCreateFunction());
		rule.setType(getType());
		rule.setCategory(getCategory());
		rule.setRecommended(getRecommended());
		rule.setSuggestion(getSuggestion());
		rule.setFixable(getFixable());
		rule.setSchema(getSchema());
		rule.setDeprecated(getDeprecated());
		rule.setReplacedBy(getReplacedBy());
		return rule;
	}
}
