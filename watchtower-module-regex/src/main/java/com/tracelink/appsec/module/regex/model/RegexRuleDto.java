package com.tracelink.appsec.module.regex.model;

import java.util.regex.Pattern;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * Represents a data transfer object for the {@link RegexRuleEntity}. All fields in this object are
 * in plain text. Contains Regex-specific fields and inherits fields from the {@link RuleDto}.
 *
 * @author mcool
 */
public class RegexRuleDto extends CustomRuleDto {

	@NotNull(message = "File extension" + CANNOT_BE_NULL)
	@Size(max = 255, message = "File extension cannot have a length of more than 256 characters.")
	private String fileExtension; // This value can be empty

	@NotNull(message = "Regex pattern" + CANNOT_BE_NULL)
	@NotEmpty(message = "Regex pattern" + CANNOT_BE_EMPTY)
	private String regexPattern;

	private Pattern compiledPattern = null;

	@Override
	public String getModule() {
		return RegexModule.REGEX_MODULE_NAME;
	}

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

	@JsonIgnore
	public Pattern getCompiledPattern() {
		if (compiledPattern == null) {
			compiledPattern = Pattern.compile(getRegexPattern());
		}
		return compiledPattern;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RegexRuleEntity toEntity() {
		RegexRuleEntity rule = new RegexRuleEntity();
		rule.setName(getName());
		rule.setMessage(getMessage());
		rule.setExternalUrl(getExternalUrl());
		rule.setPriority(getPriority());
		rule.setFileExtension(getFileExtension());
		rule.setRegexPattern(getRegexPattern());
		return rule;
	}

	/**
	 * true if null or if matches (null for match all)
	 *
	 * @param fileName the name of the file (with extension)
	 * @return true if the extension is null or matches the input string
	 */
	public boolean isValidExtension(String fileName) {
		return fileExtension.isEmpty() || fileName.endsWith(fileExtension);
	}
}
