package com.tracelink.appsec.module.regex.model;

import java.util.stream.Collectors;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

/**
 * Entity description for a Regex rule entity. Contains Regex-specific fields and inherits fields
 * from the {@link RuleEntity}.
 *
 * @author mcool
 */
@Entity
@PrimaryKeyJoinColumn(name = "rule_id")
@Table(name = "regex_rules")
public class RegexRuleEntity extends RuleEntity {

	@Column(name = "file_extension")
	private String fileExtension;

	@Column(name = "regex_pattern")
	@Convert(converter = HexStringConverter.class)
	private String regexPattern;

	// @Column(name="provided")
	private boolean provided;

	public String getFileExtension() {
		return fileExtension;
	}

	public void setFileExtension(String fileExtension) {
		this.fileExtension = fileExtension;
	}

	public String getRegexPattern() {
		return regexPattern;
	}

	public void setRegexPattern(String regexPattern) {
		this.regexPattern = regexPattern;
	}

	public boolean isProvided() {
		return provided;
	}

	public void setProvided(boolean provided) {
		this.provided = provided;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RuleDto toDto() {
		RuleDto dto;
		if (isProvided()) {
			RegexProvidedRuleDto provided = new RegexProvidedRuleDto();
			provided.setMessage(getMessage());
			provided.setExternalUrl(getExternalUrl());
			provided.setFileExtension(getFileExtension());
			provided.setRegexPattern(getRegexPattern());
			dto = provided;
		} else {
			RegexCustomRuleDto custom = new RegexCustomRuleDto();
			custom.setAuthor(getAuthor());
			custom.setMessage(getMessage());
			custom.setExternalUrl(getExternalUrl());
			custom.setFileExtension(getFileExtension());
			custom.setRegexPattern(getRegexPattern());
			dto = custom;
		}
		// Set inherited fields
		dto.setId(getId());
		dto.setName(getName());
		dto.setPriority(getPriority());
		dto.setRulesets(
				getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
		return dto;
	}
}
