package com.tracelink.appsec.module.checkov.model;

import java.util.stream.Collectors;

import javax.persistence.Column;
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

	@Column(name = "checkovrulename")
	private String checkovRuleName;

	@Column(name = "checkovtype")
	private String type;

	@Column(name = "entity")
	private String entity;

	@Column(name = "iac")
	private String iac;

	@Override
	public CheckovProvidedRuleDto toDto() {
		// Set inherited fields
		CheckovProvidedRuleDto dto = new CheckovProvidedRuleDto();
		dto.setId(getId());
		dto.setName(getName());
		dto.setCheckovRuleName(getCheckovRuleName());
		dto.setMessage(getMessage());
		dto.setGuidelineUrl(getExternalUrl());
		dto.setPriority(getPriority());
		dto.setRulesets(
				getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
		// Set Checkov-specific fields
		dto.setCheckovType(getType());
		dto.setCheckovEntity(getEntity());
		dto.setCheckovIac(getIac());
		return dto;
	}

	public String getCheckovRuleName() {
		return checkovRuleName;
	}

	public void setCheckovRuleName(String checkovRuleName) {
		this.checkovRuleName = checkovRuleName;
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

}
