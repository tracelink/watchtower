package com.tracelink.appsec.module.regex.model;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import java.util.stream.Collectors;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.Table;

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

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RegexRuleDto toDto() {
		RegexRuleDto dto = new RegexRuleDto();
		// Set inherited fields
		dto.setId(getId());
		dto.setAuthor(getAuthor());
		dto.setName(getName());
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(getPriority());
		dto.setRulesets(
				getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
		// Set Regex-specific fields
		dto.setFileExtension(getFileExtension());
		dto.setRegexPattern(getRegexPattern());
		return dto;
	}
}
