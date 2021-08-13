package com.tracelink.appsec.module.checkov.model;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.tracelink.appsec.module.checkov.CheckovModule;
import com.tracelink.appsec.watchtower.core.rule.ProvidedRuleDto;

/**
 * Extension of the {@linkplain ProvidedRuleDto} to add Checkov Rule concepts like the
 * categorization of the rule
 * 
 * @author csmith
 *
 */
public class CheckovProvidedRuleDto extends ProvidedRuleDto {
	private String message;
	private String externalUrl;
	private List<CheckovRuleDefinitionDto> definitions = new ArrayList<>();

	@Override
	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public void setExternalUrl(String url) {
		this.externalUrl = url;
	}

	@Override
	public String getExternalUrl() {
		return externalUrl;
	}

	public void setDefinitions(List<CheckovRuleDefinitionDto> definitions) {
		this.definitions = definitions;
	}

	public List<CheckovRuleDefinitionDto> getDefinitions() {
		return definitions;
	}

	@Override
	public String getModule() {
		return CheckovModule.MODULE_NAME;
	}

	@Override
	public CheckovRuleEntity toEntity() {
		if (isProvided()) {
			CheckovRuleEntity rule = new CheckovRuleEntity();
			rule.setName(getName());
			rule.setAuthor(getAuthor());
			rule.setProvided(isProvided());
			rule.setMessage(getMessage());
			rule.setExternalUrl(getExternalUrl());
			rule.setPriority(getPriority());
			rule.setDefinitions(getDefinitions().stream().map(CheckovRuleDefinitionDto::toEntity)
					.collect(Collectors.toSet()));
			return rule;
		} else {
			throw new IllegalArgumentException("Checkov does not support Custom Rules");
		}
	}

}
