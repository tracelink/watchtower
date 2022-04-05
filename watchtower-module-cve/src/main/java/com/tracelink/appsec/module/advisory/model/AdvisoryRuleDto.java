package com.tracelink.appsec.module.advisory.model;

import com.tracelink.appsec.module.advisory.AdvisoryModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;

public class AdvisoryRuleDto extends CustomRuleDto {

	private AdvisoryType advisoryType;

	private String packageName;

	private String score;

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
	public String getModule() {
		return AdvisoryModule.MODULE_NAME;
	}

	@Override
	public AdvisoryRuleEntity toEntity() {
		AdvisoryRuleEntity entity = new AdvisoryRuleEntity();
		entity.setId(getId());
		entity.setName(getName());
		entity.setMessage(getMessage());
		entity.setExternalUrl(getExternalUrl());
		entity.setPriority(getPriority());
		entity.setAdvisoryType(getAdvisoryType());
		entity.setPackageName(getPackageName());
		entity.setScore(getScore());
		entity.setVector(getVector());
		return entity;
	}

}
