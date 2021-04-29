package com.tracelink.appsec.module.regex.xml;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlCData;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.tracelink.appsec.module.regex.model.RegexRuleDto;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRuleImpexModel;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Implementation of an {@linkplain AbstractRuleImpexModel} that represents a Regex rule.
 *
 * @author mcool
 */
public class RegexRuleXmlModel extends AbstractRuleImpexModel {
	@JacksonXmlProperty(isAttribute = true)
	private String name;
	@JacksonXmlProperty
	private String message;
	@JacksonXmlProperty
	private String extension;
	@JacksonXmlProperty
	@JacksonXmlCData
	private String pattern;
	@JacksonXmlProperty(localName = "externalURL")
	private String externalUrl;
	@JacksonXmlProperty
	private int priority;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message.trim();
	}

	public String getExtension() {
		return extension;
	}

	public void setExtension(String extension) {
		this.extension = extension.trim();
	}

	public String getPattern() {
		return pattern;
	}

	public void setPattern(String pattern) {
		this.pattern = pattern.trim();
	}

	public String getExternalUrl() {
		return externalUrl;
	}

	public void setExternalUrl(String externalUrl) {
		this.externalUrl = externalUrl.trim();
	}

	public int getPriority() {
		return priority;
	}

	public void setPriority(int priority) {
		this.priority = priority;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RuleDto toDto() {
		RegexRuleDto dto = new RegexRuleDto();
		dto.setName(getName());
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(RulePriority.valueOf(getPriority()));
		dto.setFileExtension(getExtension());
		dto.setRegexPattern(getPattern());
		return dto;
	}
}
