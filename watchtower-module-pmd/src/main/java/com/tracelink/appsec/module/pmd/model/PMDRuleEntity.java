package com.tracelink.appsec.module.pmd.model;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Table;

/**
 * Entity description for a PMD rule entity. Contains PMD-specific fields and inherits fields from
 * the {@link RuleEntity}.
 *
 * @author mcool
 */
@Entity
@Table(name = "pmd_rules")
public class PMDRuleEntity extends RuleEntity {

	@Column(name = "parser_language")
	private String parserLanguage;

	@Column(name = "rule_class")
	private String ruleClass;

	@Column(name = "description")
	@Convert(converter = HexStringConverter.class)
	private String description;

	@OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
	@JoinColumn(name = "rule_id", nullable = false)
	private List<PMDPropertyEntity> properties = new ArrayList<>();

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

	public List<PMDPropertyEntity> getProperties() {
		return properties;
	}

	public void setProperties(List<PMDPropertyEntity> properties) {
		this.properties = properties;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PMDRuleDto toDto() {
		PMDRuleDto dto = new PMDRuleDto();
		// Set inherited fields
		dto.setId(getId());
		dto.setAuthor(getAuthor());
		dto.setName(getName());
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(getPriority());
		dto.setRulesets(
				getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
		// Set PMD-specific fields
		dto.setParserLanguage(getParserLanguage());
		dto.setRuleClass(getRuleClass());
		dto.setDescription(getDescription());
		dto.setProperties(getProperties().stream().map(PMDPropertyEntity::toDto)
				.collect(Collectors.toList()));
		return dto;
	}
}
