package com.tracelink.appsec.module.advisory.model;

import com.tracelink.appsec.module.advisory.AdvisoryModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityFinding;

/**
 * A Rule definition to identity if a {@linkplain ImageSecurityFinding} fails this rule and also
 * transfer between this class and the underlying Entity
 * 
 * @author csmith
 *
 */
public class AdvisoryRuleDto extends CustomRuleDto {

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

	/**
	 * true if the given finding matches this DTO's name
	 * 
	 * @param finding the finding to check
	 * @return true if the finding's name matches this name, false otherwise
	 */
	public boolean matches(ImageSecurityFinding finding) {
		return finding.getFindingName().equalsIgnoreCase(getName());
	}
}
