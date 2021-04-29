package com.tracelink.appsec.module.checkov.model;

import java.util.stream.Collectors;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

/**
 * Entity definition of a Checkov Rule
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "checkov_rules")
public class CheckovRuleEntity extends RuleEntity {

	@Column(name = "core")
	private boolean coreRule;

	@Column(name = "checkovtype")
	private String type;

	@Column(name = "entity")
	private String entity;

	@Column(name = "iac")
	private String iac;

	@Column(name = "code")
	@Convert(converter = HexStringConverter.class)
	private String code;

	@Override
	public CheckovRuleDto toDto() {
		// Set inherited fields
		CheckovRuleDto dto = new CheckovRuleDto();
		dto.setId(getId());
		dto.setAuthor(getAuthor());
		dto.setName(getName());
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(getPriority());
		dto.setRulesets(
				getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
		// Set Checkov-specific fields
		dto.setCoreRule(isCoreRule());
		dto.setCheckovType(getType());
		dto.setCheckovEntity(getEntity());
		dto.setCheckovIac(getIac());
		dto.setCode(getCode());
		return dto;
	}

	public boolean isCoreRule() {
		return coreRule;
	}

	public void setCoreRule(boolean coreRule) {
		this.coreRule = coreRule;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getEntity() {
		return entity;
	}

	public void setEntity(String entity) {
		this.entity = entity;
	}

	public String getIac() {
		return iac;
	}

	public void setIac(String iac) {
		this.iac = iac;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}
}
