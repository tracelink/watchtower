package com.tracelink.appsec.module.eslint.model;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

/**
 * Entity description for an ESLint rule entity. Contains ESLint-specific fields and inherits fields
 * from the {@link RuleEntity}.
 *
 * @author mcool
 */
@Entity
@Table(name = "eslint_rules")
public class EsLintRuleEntity extends RuleEntity {

	@Column(name = "core")
	private boolean core;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, orphanRemoval = true)
	@JoinColumn(name = "rule_id", nullable = false)
	private Set<EsLintMessageEntity> messages = new LinkedHashSet<>();

	@Column(name = "create_function")
	@Convert(converter = HexStringConverter.class)
	private String createFunction;

	/*
	 * OPTIONAL FIELDS The remaining fields are included in the ESLint rule model, but are not
	 * useful for Watchtower. They are included here to support compatibility with preexisting rules
	 * so that we do not lose any information on ruleset import/export.
	 */

	@Column(name = "rule_type")
	@Enumerated(value = EnumType.STRING)
	private EsLintRuleType type;

	@Column(name = "category")
	private String category;

	@Column(name = "recommended")
	private Boolean recommended;

	@Column(name = "suggestion")
	private Boolean suggestion;

	@Column(name = "fixable")
	@Enumerated(value = EnumType.STRING)
	private EsLintRuleFixable fixable;

	@Column(name = "rule_schema")
	@Convert(converter = HexStringConverter.class)
	private String schema = "[]";

	@Column(name = "deprecated")
	private Boolean deprecated;

	@Column(name = "replaced_by")
	@Convert(converter = HexStringConverter.class)
	private String replacedBy;

	/*
	 * END OPTIONAL FIELDS
	 */

	public boolean isCore() {
		return core;
	}

	public void setCore(boolean core) {
		this.core = core;
	}

	public Set<EsLintMessageEntity> getMessages() {
		return messages;
	}

	public void setMessages(Set<EsLintMessageEntity> messages) {
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
	public EsLintRuleDto toDto() {
		EsLintRuleDto dto = new EsLintRuleDto();
		// Set inherited fields
		dto.setId(getId());
		dto.setAuthor(getAuthor());
		dto.setName(getName());
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(getPriority());
		dto.setRulesets(
				getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
		// Set ESLint-specific fields
		dto.setCore(isCore());
		dto.setMessages(
				getMessages().stream().map(EsLintMessageEntity::toDto)
						.collect(Collectors.toList()));
		dto.setCreateFunction(getCreateFunction());
		dto.setType(getType());
		dto.setCategory(getCategory());
		dto.setRecommended(getRecommended());
		dto.setSuggestion(getSuggestion());
		dto.setFixable(getFixable());
		dto.setSchema(getSchema());
		dto.setDeprecated(getDeprecated());
		dto.setReplacedBy(getReplacedBy());
		return dto;
	}
}
