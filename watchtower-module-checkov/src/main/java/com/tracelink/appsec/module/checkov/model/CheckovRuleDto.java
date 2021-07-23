package com.tracelink.appsec.module.checkov.model;

import com.tracelink.appsec.module.checkov.CheckovModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * Extension of the {@linkplain RuleDto} to add Checkov Rule concepts like being a core rule and the
 * categorization of the rule
 * 
 * @author csmith
 *
 */
public class CheckovRuleDto extends CustomRuleDto {

	private boolean coreRule;
	private String type;
	private String entity;
	private String iac;
	private String code;

	@Override
	public String getModule() {
		return CheckovModule.MODULE_NAME;
	}

	@Override
	public CheckovRuleEntity toEntity() {
		CheckovRuleEntity rule = new CheckovRuleEntity();
		// Set inherited fields
		rule.setName(getName());
		rule.setAuthor(getAuthor());
		rule.setMessage(getMessage());
		rule.setExternalUrl(getExternalUrl());
		rule.setPriority(getPriority());
		// Set Checkov-specific fields
		rule.setCoreRule(isCoreRule());
		rule.setType(getCheckovType());
		rule.setEntity(getCheckovEntity());
		rule.setIac(getCheckovIac());
		rule.setCode(getCode());
		return rule;
	}

	public boolean isCoreRule() {
		return coreRule;
	}

	public void setCoreRule(boolean coreRule) {
		this.coreRule = coreRule;
	}

	public String getCheckovType() {
		return type;
	}

	public void setCheckovType(String type) {
		this.type = type;
	}

	public String getCheckovEntity() {
		return entity;
	}

	public void setCheckovEntity(String entity) {
		this.entity = entity;
	}

	public String getCheckovIac() {
		return iac;
	}

	public void setCheckovIac(String iac) {
		this.iac = iac;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

}
