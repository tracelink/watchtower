package com.tracelink.appsec.module.eslint.model;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
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

	@Column(name = "rule_schema")
	@Convert(converter = HexStringConverter.class)
	private String schema = "[]";

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

	public String getSchema() {
		return schema;
	}

	public void setSchema(String schema) {
		this.schema = schema;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RuleDto toDto() {
		RuleDto rule;
		if (isCore()) {
			EsLintProvidedRuleDto dto = new EsLintProvidedRuleDto();
			dto.setMessage(getMessage());
			dto.setExternalUrl(getExternalUrl());
			rule = dto;
		} else {
			EsLintCustomRuleDto dto = new EsLintCustomRuleDto();
			dto.setAuthor(getAuthor());
			dto.setMessage(getMessage());
			dto.setExternalUrl(getExternalUrl());
			dto.setMessages(
					getMessages().stream().map(EsLintMessageEntity::toDto)
							.collect(Collectors.toList()));
			dto.setCreateFunction(getCreateFunction());
			dto.setSchema(getSchema());
			rule = dto;
		}
		rule.setId(getId());
		rule.setName(getName());
		rule.setPriority(getPriority());
		rule.setRulesets(
				getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
		return rule;
	}
}
