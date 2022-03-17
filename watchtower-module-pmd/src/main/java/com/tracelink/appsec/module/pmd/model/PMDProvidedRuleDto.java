package com.tracelink.appsec.module.pmd.model;

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.watchtower.core.rule.ProvidedRuleDto;

/**
 * Rule definition of a PMD-provided rule. Hold basic information about the underlying PMD rule
 * 
 * @author csmith
 *
 */
public class PMDProvidedRuleDto extends ProvidedRuleDto implements PMDRuleDto {

	private String message;

	private String externalUrl;

	@Override
	public String getModule() {
		return PMDModule.PMD_MODULE_NAME;
	}

	@Override
	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	@Override
	public String getExternalUrl() {
		return externalUrl;
	}

	public void setExternalUrl(String externalUrl) {
		this.externalUrl = externalUrl;
	}

	@Override
	public PMDRuleEntity toEntity() {
		PMDRuleEntity rule = new PMDRuleEntity();
		rule.setAuthor(getAuthor());
		rule.setName(getName());
		rule.setMessage(getMessage());
		rule.setPriority(getPriority());
		rule.setProvided(isProvided());
		rule.setExternalUrl(getExternalUrl());
		return rule;
	}

}

