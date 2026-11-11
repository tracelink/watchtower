package com.tracelink.appsec.module.checkov.model;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

/**
 * Entity definition of a Checkov Rule
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "checkov_rules")
public class CheckovRuleEntity extends RuleEntity {
	@Column(name = "provided")
	private boolean provided;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, orphanRemoval = true)
	@JoinColumn(name = "rule_id", nullable = false)
	private Set<CheckovRuleDefinitionEntity> definitions = new LinkedHashSet<>();

	public boolean isProvided() {
		return provided;
	}

	public void setProvided(boolean provided) {
		this.provided = provided;
	}

	public Set<CheckovRuleDefinitionEntity> getDefinitions() {
		return definitions;
	}

	public void setDefinitions(Set<CheckovRuleDefinitionEntity> definitions) {
		this.definitions = definitions;
	}

	@Override
	public CheckovProvidedRuleDto toDto() {
		if (isProvided()) {
			// Set inherited fields
			CheckovProvidedRuleDto dto = new CheckovProvidedRuleDto();
			dto.setId(getId());
			dto.setName(getName());
			dto.setMessage(getMessage());
			dto.setExternalUrl(getExternalUrl());
			dto.setPriority(getPriority());
			dto.setRulesets(
					getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
			dto.setDefinitions(getDefinitions().stream().map(CheckovRuleDefinitionEntity::toDto)
					.collect(Collectors.toList()));
			return withStewardship(dto);
		} else {
			throw new IllegalArgumentException("Checkov does not support custom rules");
		}
	}

}
