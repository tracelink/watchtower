package com.tracelink.appsec.module.advisory.model;

import java.util.stream.Collectors;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Table;

import com.tracelink.appsec.module.advisory.model.AdvisoryType.AdvisoryTypeConverter;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

@Entity
@Table(name = "cve_rules")
public class AdvisoryRuleEntity extends RuleEntity {

	@Column(name = "advisory_type")
	@Convert(converter = AdvisoryTypeConverter.class)
	private AdvisoryType advisoryType;

	@Column(name = "package_name")
	private String packageName;

	@Column(name = "score")
	private String score;

	@Column(name = "vector")
	private String vector;

	public AdvisoryType getAdvisoryType() {
		return advisoryType;
	}

	public void setAdvisoryType(AdvisoryType advisoryType) {
		this.advisoryType = advisoryType;
	}

	public String getPackageName() {
		return packageName;
	}

	public void setPackageName(String packageName) {
		this.packageName = packageName;
	}

	public String getScore() {
		return score;
	}

	public void setScore(String score) {
		this.score = score;
	}

	public String getVector() {
		return vector;
	}

	public void setVector(String vector) {
		this.vector = vector;
	}

	@Override
	public AdvisoryRuleDto toDto() {
		AdvisoryRuleDto dto = new AdvisoryRuleDto();
		dto.setId(getId());
		dto.setName(getName());
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(getPriority());
		dto.setRulesets(
				getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
		dto.setPackageName(getPackageName());
		dto.setScore(getScore());
		dto.setVector(getVector());
		return dto;
	}

	@Override
	public String toString() {
		return getName() + " - " + getPackageName();
	}
}
