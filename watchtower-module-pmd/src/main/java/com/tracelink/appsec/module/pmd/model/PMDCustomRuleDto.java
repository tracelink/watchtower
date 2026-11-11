package com.tracelink.appsec.module.pmd.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.LanguageScopedRule;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;

/**
 * Represents a data transfer object for the {@link PMDRuleEntity}. All fields in this object are in
 * plain text. Contains PMD-specific fields and inherits fields from the {@link RuleDto}.
 *
 * @author mcool
 */
public class PMDCustomRuleDto extends CustomRuleDto implements PMDRuleDto, LanguageScopedRule {

	@NotNull(message = "Parser language" + CANNOT_BE_NULL)
	@NotEmpty(message = "Parser language" + CANNOT_BE_EMPTY)
	private String parserLanguage;

	@NotNull(message = "Rule class" + CANNOT_BE_NULL)
	@NotEmpty(message = "Rule class" + CANNOT_BE_EMPTY)
	@Size(max = 255, message = "Rule class cannot have a length of more than 256 characters.")
	private String ruleClass;

	private List<@Valid PMDPropertyDto> properties = new ArrayList<>();

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

	@Override
	public Set<String> scannedLanguages() {
		return parserLanguage == null || parserLanguage.isBlank() ? Set.of()
				: Set.of(parserLanguage.trim().toLowerCase(Locale.ROOT));
	}

	public String getRuleClass() {
		return ruleClass;
	}

	public void setRuleClass(String ruleClass) {
		this.ruleClass = ruleClass;
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
		rule.setProvided(isProvided());
		rule.setParserLanguage(getParserLanguage());
		rule.setRuleClass(getRuleClass());
		rule.setProperties(getProperties().stream().map(PMDPropertyDto::toEntity)
				.collect(Collectors.toSet()));
		return rule;
	}


	@Override
	protected RuleRevision executableDefinition() {
		// Duplicate parameter names have order-dependent behavior and no reliable set ordering.
		if (getProperties().stream().map(PMDPropertyDto::getName).distinct().count()
				!= getProperties().size()) {
			return null;
		}
		return newDefinition().field("parserLanguage", getParserLanguage())
				.field("ruleClass", getRuleClass())
				.unordered("properties", getProperties().stream().map(property ->
						RuleRevision.definition("pmd-property", "parameter")
								.field("name", property.getName())
								.field("value", property.getValue()).hash()).toList());
	}
}
