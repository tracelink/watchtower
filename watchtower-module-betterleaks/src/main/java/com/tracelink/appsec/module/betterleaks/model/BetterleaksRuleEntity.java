package com.tracelink.appsec.module.betterleaks.model;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

/**
 * Persisted Betterleaks rule: a provided rule from the pinned default config, or a custom rule
 * written in the designer (which also carries its detection fields and samples).
 *
 * @author Watchtower
 */
@Entity
@Table(name = "betterleaks_rules")
public class BetterleaksRuleEntity extends RuleEntity {

	@Column(name = "provided")
	private boolean provided;

	@Column(name = "betterleaks_id")
	private String betterleaksId;

	@Column(name = "category")
	@Enumerated(EnumType.STRING)
	private BetterleaksCategory category;

	@Column(name = "confidence")
	private String confidence;

	@Column(name = "regex")
	private String regex;

	/** Comma-joined; keywords cannot contain commas. */
	@Column(name = "keywords")
	private String keywords;

	@Column(name = "entropy")
	private Double entropy;

	@Column(name = "secret_group")
	private Integer secretGroup;

	@Column(name = "cel_filter")
	private String filter;

	@Column(name = "positive_sample")
	private String positiveSample;

	@Column(name = "negative_sample")
	private String negativeSample;

	@Column(name = "rule_version")
	private Integer ruleVersion;

	public boolean isProvided() {
		return provided;
	}

	public void setProvided(boolean provided) {
		this.provided = provided;
	}

	public String getBetterleaksId() {
		return betterleaksId;
	}

	public void setBetterleaksId(String betterleaksId) {
		this.betterleaksId = betterleaksId;
	}

	public BetterleaksCategory getCategory() {
		return category;
	}

	public void setCategory(BetterleaksCategory category) {
		this.category = category;
	}

	public String getConfidence() {
		return confidence;
	}

	public void setConfidence(String confidence) {
		this.confidence = confidence;
	}

	public String getRegex() {
		return regex;
	}

	public void setRegex(String regex) {
		this.regex = regex;
	}

	public String getKeywords() {
		return keywords;
	}

	public void setKeywords(String keywords) {
		this.keywords = keywords;
	}

	public Double getEntropy() {
		return entropy;
	}

	public void setEntropy(Double entropy) {
		this.entropy = entropy;
	}

	public Integer getSecretGroup() {
		return secretGroup;
	}

	public void setSecretGroup(Integer secretGroup) {
		this.secretGroup = secretGroup;
	}

	public String getFilter() {
		return filter;
	}

	public void setFilter(String filter) {
		this.filter = filter;
	}

	public String getPositiveSample() {
		return positiveSample;
	}

	public void setPositiveSample(String positiveSample) {
		this.positiveSample = positiveSample;
	}

	public String getNegativeSample() {
		return negativeSample;
	}

	public void setNegativeSample(String negativeSample) {
		this.negativeSample = negativeSample;
	}

	public Integer getRuleVersion() {
		return ruleVersion;
	}

	public void setRuleVersion(Integer ruleVersion) {
		this.ruleVersion = ruleVersion;
	}

	@Override
	public com.tracelink.appsec.watchtower.core.rule.RuleDto toDto() {
		return withStewardship(provided ? toProvidedDto() : toCustomDto());
	}

	private Set<String> rulesetNames() {
		return getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet());
	}

	private BetterleaksProvidedRuleDto toProvidedDto() {
		BetterleaksProvidedRuleDto dto = new BetterleaksProvidedRuleDto();
		dto.setId(getId());
		dto.setName(getName());
		dto.setBetterleaksId(betterleaksId);
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(getPriority());
		dto.setCategory(category);
		dto.setConfidence(confidence);
		dto.setRulesets(rulesetNames());
		return dto;
	}

	private BetterleaksCustomRuleDto toCustomDto() {
		BetterleaksCustomRuleDto dto = new BetterleaksCustomRuleDto();
		dto.setId(getId());
		dto.setName(getName());
		dto.setAuthor(getAuthor());
		dto.setBetterleaksId(betterleaksId);
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(getPriority());
		dto.setRegex(regex);
		dto.setKeywords(StringUtils.isBlank(keywords) ? List.of()
				: Arrays.asList(keywords.split(",")));
		dto.setEntropy(entropy);
		dto.setSecretGroup(secretGroup);
		dto.setFilter(filter);
		dto.setPositiveSample(positiveSample);
		dto.setNegativeSample(negativeSample);
		dto.setVersion(ruleVersion == null ? 1 : ruleVersion);
		dto.setRulesets(rulesetNames());
		return dto;
	}
}
