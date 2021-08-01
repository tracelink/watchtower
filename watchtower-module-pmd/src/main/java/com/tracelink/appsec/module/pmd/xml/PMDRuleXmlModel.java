package com.tracelink.appsec.module.pmd.xml;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlCData;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRuleImpexModel;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Implementation of an {@linkplain AbstractRuleImpexModel} that represents a PMD rule.
 *
 * @author mcool
 */

public class PMDRuleXmlModel extends AbstractRuleImpexModel {
	@JacksonXmlProperty(isAttribute = true)
	private String name;
	@JacksonXmlProperty(isAttribute = true)
	private String since = "1.0";
	@JacksonXmlProperty(isAttribute = true)
	private String language;
	@JacksonXmlProperty(isAttribute = true)
	private String message;
	@JacksonXmlProperty(localName = "class", isAttribute = true)
	private String clazz;
	@JacksonXmlProperty(localName = "externalInfoUrl", isAttribute = true)
	private String externalUrl;
	private String description;
	private int priority;
	@JacksonXmlElementWrapper(localName = "properties")
	@JacksonXmlProperty(localName = "property")
	private List<Property> properties = new ArrayList<>();
	@JacksonXmlCData
	private String example = "";

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getSince() {
		return since;
	}

	public void setSince(String since) {
		this.since = since;
	}

	public String getLanguage() {
		return language;
	}

	public void setLanguage(String language) {
		this.language = language;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getClazz() {
		return clazz;
	}

	public void setClazz(String clazz) {
		this.clazz = clazz;
	}

	public String getExternalUrl() {
		return externalUrl;
	}

	public void setExternalUrl(String externalUrl) {
		this.externalUrl = externalUrl;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description.trim();
	}

	public int getPriority() {
		return priority;
	}

	public void setPriority(int priority) {
		this.priority = priority;
	}

	public List<Property> getProperties() {
		return properties;
	}

	public void setProperties(List<Property> properties) {
		this.properties = properties;
	}

	public String getExample() {
		return example;
	}

	public void setExample(String example) {
		this.example = example.trim();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RuleDto toDto() {
		PMDCustomRuleDto dto = new PMDCustomRuleDto();
		dto.setName(getName());
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(RulePriority.valueOf(getPriority()));
		dto.setParserLanguage(getLanguage());
		dto.setRuleClass(getClazz());
		// dto.setDescription(getDescription());
		dto.setProperties(getProperties().stream().map(property -> {
			PMDPropertyDto pmdProperty = new PMDPropertyDto();
			pmdProperty.setName(property.getName());
			pmdProperty.setValue(property.getValue());
			return pmdProperty;
		}).collect(Collectors.toList()));
		return dto;
	}
}
