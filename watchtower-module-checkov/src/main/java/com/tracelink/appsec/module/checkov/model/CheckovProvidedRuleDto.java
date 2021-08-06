package com.tracelink.appsec.module.checkov.model;

import com.tracelink.appsec.module.checkov.CheckovModule;
import com.tracelink.appsec.watchtower.core.rule.ProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * Extension of the {@linkplain ProvidedRuleDto} to add Checkov Rule concepts like the
 * categorization of the rule
 * 
 * @author csmith
 *
 */
public class CheckovProvidedRuleDto extends ProvidedRuleDto {
	private String ruleName;
	private String message;
	private String type;
	private String entity;
	private String iac;
	private String externalUrl;

	public String getCheckovRuleName() {
		return this.ruleName;
	}

	public void setCheckovRuleName(String ruleName) {
		this.ruleName = ruleName;
	}

	@Override
	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
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

	public void setExternalUrl(String url) {
		this.externalUrl = url;
	}

	@Override
	public String getExternalUrl() {
		return externalUrl;
	}

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
		rule.setType(getCheckovType());
		rule.setEntity(getCheckovEntity());
		rule.setIac(getCheckovIac());
		return rule;
	}

	@Override
	public int compareTo(RuleDto o) {
		if (o instanceof CheckovProvidedRuleDto) {
			CheckovProvidedRuleDto other = (CheckovProvidedRuleDto) o;
			return (getCheckovIac() + getName()).compareTo(other.getCheckovIac() + other.getName());
		}
		return super.compareTo(o);
	}

}
