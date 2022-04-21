package com.tracelink.appsec.module.advisory.model;

import com.tracelink.appsec.module.advisory.AdvisoryModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityFinding;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;

public class AdvisoryRuleDto extends CustomRuleDto {

	public AdvisoryRuleDto() {

	}

	public AdvisoryRuleDto(AdvisoryEntity advisory) {
		setExternalUrl(advisory.getUri());
		setMessage(advisory.getDescription());
		setName(advisory.getAdvisoryName());
	}

	@Override
	public String getModule() {
		return AdvisoryModule.ADVISORY_MODULE_NAME;
	}

	@Override
	public AdvisoryRuleEntity toEntity() {
		AdvisoryRuleEntity ruleEntity = new AdvisoryRuleEntity();
		ruleEntity.setAuthor(getAuthor());
		ruleEntity.setExternalUrl(getExternalUrl());
		ruleEntity.setMessage(getMessage());
		ruleEntity.setName(getName());
		ruleEntity.setPriority(getPriority());
		return ruleEntity;
	}

	public boolean matches(ImageSecurityFinding finding) {
		return finding.getFindingName().equalsIgnoreCase(getName());
	}


}
