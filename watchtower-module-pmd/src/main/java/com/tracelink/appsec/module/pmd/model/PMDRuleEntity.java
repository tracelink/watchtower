package com.tracelink.appsec.module.pmd.model;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

/**
 * Entity description for a PMD rule entity. Contains PMD-specific fields and inherits fields from
 * the {@link RuleEntity}.
 *
 * @author mcool
 */
@Entity
@Table(name = "pmd_rules")
public class PMDRuleEntity extends RuleEntity {
	@Column(name = "provided")
	private boolean provided;

	@Column(name = "parser_language")
	private String parserLanguage;

	@Column(name = "rule_class")
	private String ruleClass;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, orphanRemoval = true)
	@JoinColumn(name = "rule_id", nullable = false)
	private Set<PMDPropertyEntity> properties = new LinkedHashSet<>();

	public boolean isProvided() {
		return provided;
	}

	public void setProvided(boolean provided) {
		this.provided = provided;
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

	public Set<PMDPropertyEntity> getProperties() {
		return properties;
	}

	public void setProperties(Set<PMDPropertyEntity> properties) {
		this.properties = properties;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RuleDto toDto() {
		if (isProvided()) {
			PMDProvidedRuleDto providedDto = new PMDProvidedRuleDto();
			providedDto.setId(getId());
			providedDto.setName(getName());
			providedDto.setMessage(getMessage());
			providedDto.setExternalUrl(getExternalUrl());
			providedDto.setPriority(getPriority());
			providedDto.setRulesets(
					getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
			return providedDto;
		} else {
			PMDCustomRuleDto dto = new PMDCustomRuleDto();
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
			dto.setProperties(getProperties().stream().map(PMDPropertyEntity::toDto)
					.collect(Collectors.toList()));
			return dto;
		}
	}
}
