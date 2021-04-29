package com.tracelink.appsec.module.pmd.model;

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * Represents a data transfer object for the {@link PMDRuleEntity}. All fields in this object are in
 * plain text.
 * Contains PMD-specific fields and inherits fields from the {@link RuleDto}.
 *
 * @author mcool
 */
public class PMDRuleDto extends RuleDto {

	@NotNull(message = "Parser language" + CANNOT_BE_NULL)
	@NotEmpty(message = "Parser language" + CANNOT_BE_EMPTY)
	private String parserLanguage;

	@NotNull(message = "Rule class" + CANNOT_BE_NULL)
	@NotEmpty(message = "Rule class" + CANNOT_BE_EMPTY)
	@Size(max = 255, message = "Rule class cannot have a length of more than 256 characters.")
	private String ruleClass;

	@NotNull(message = "Description" + CANNOT_BE_NULL)
	@NotEmpty(message = "Description" + CANNOT_BE_EMPTY)
	private String description;

	@Valid
	private List<PMDPropertyDto> properties = new ArrayList<>();

	@Override
	public String getModule() {
		return PMDModule.PMD_MODULE_NAME;
	}

	public String getParserLanguage() {
		return parserLanguage;
	}

	public void setParserLanguage(String parserLanguage) {
		this.parserLanguage = parserLanguage;
	}

	public String getRuleClass() {
		return ruleClass;
	}

	public void setRuleClass(String ruleClass) {
		this.ruleClass = ruleClass;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public List<PMDPropertyDto> getProperties() {
		return properties;
	}

	public void setProperties(List<PMDPropertyDto> properties) {
		this.properties = properties;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PMDRuleEntity toEntity() {
		PMDRuleEntity rule = new PMDRuleEntity();
		rule.setName(getName());
		rule.setMessage(getMessage());
		rule.setExternalUrl(getExternalUrl());
		rule.setPriority(getPriority());
		rule.setParserLanguage(getParserLanguage());
		rule.setRuleClass(getRuleClass());
		rule.setDescription(getDescription());
		rule.setProperties(getProperties().stream().map(PMDPropertyDto::toEntity)
				.collect(Collectors.toList()));
		return rule;
	}
}
