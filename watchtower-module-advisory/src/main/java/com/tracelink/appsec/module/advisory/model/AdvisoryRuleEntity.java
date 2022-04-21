package com.tracelink.appsec.module.advisory.model;

import javax.persistence.Entity;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

@Entity
@Table(name = "advisory_rules")
public class AdvisoryRuleEntity extends RuleEntity {

	@Override
	public AdvisoryRuleDto toDto() {
		AdvisoryRuleDto ruleDto = new AdvisoryRuleDto();
		ruleDto.setAuthor(getAuthor());
		ruleDto.setExternalUrl(getExternalUrl());
		ruleDto.setMessage(getMessage());
		ruleDto.setName(getName());
		ruleDto.setPriority(getPriority());
		ruleDto.setId(getId());
		return ruleDto;
	}

}
