package com.tracelink.appsec.module.betterleaks.designer;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * The custom-rule form shared by the designer and the editor: raw strings as submitted, turned
 * into a rule by {@link #toRule()}. Parse errors never echo the submitted value.
 *
 * @author Watchtower
 */
public class BetterleaksCustomRuleForm {

	private Long id;

	private String ruleId;

	private String description;

	private String externalUrl;

	private String priority;

	private String regex;

	private String keywords;

	private String entropy;

	private String secretGroup;

	private String filter;

	private String positiveSample;

	private String negativeSample;

	/**
	 * @param rule an existing rule
	 * @return a form pre-filled with it
	 */
	public static BetterleaksCustomRuleForm fromRule(BetterleaksCustomRuleDto rule) {
		BetterleaksCustomRuleForm form = new BetterleaksCustomRuleForm();
		form.setId(rule.getId());
		form.setRuleId(rule.getBetterleaksId());
		form.setDescription(rule.getMessage());
		form.setExternalUrl(rule.getExternalUrl());
		form.setPriority(rule.getPriority() == null ? null : rule.getPriority().name());
		form.setRegex(rule.getRegex());
		form.setKeywords(String.join(", ", rule.getKeywords()));
		form.setEntropy(rule.getEntropy() == null ? null : rule.getEntropy().toString());
		form.setSecretGroup(rule.getSecretGroup() == null ? null : rule.getSecretGroup().toString());
		form.setFilter(rule.getFilter());
		form.setPositiveSample(rule.getPositiveSample());
		form.setNegativeSample(rule.getNegativeSample());
		return form;
	}

	/**
	 * @return the rule the form describes; not yet validated (see
	 *         {@link BetterleaksCustomRuleDto#fieldProblems()})
	 * @throws IllegalArgumentException if a number or the priority cannot be read
	 */
	public BetterleaksCustomRuleDto toRule() {
		String betterleaksId = StringUtils.trimToEmpty(ruleId);
		BetterleaksCustomRuleDto rule = new BetterleaksCustomRuleDto();
		rule.setId(id);
		rule.setBetterleaksId(betterleaksId);
		rule.setName(BetterleaksRuleDto.NAME_PREFIX + betterleaksId);
		rule.setMessage(StringUtils.trimToNull(description));
		rule.setExternalUrl(StringUtils.trimToNull(externalUrl));
		rule.setPriority(parsePriority(priority));
		rule.setRegex(StringUtils.trimToNull(regex));
		rule.setKeywords(parseKeywords(keywords));
		rule.setEntropy(parseDouble(entropy, "Entropy"));
		rule.setSecretGroup(parseInteger(secretGroup, "The secret group"));
		rule.setFilter(StringUtils.trimToNull(filter));
		rule.setPositiveSample(positiveSample);
		rule.setNegativeSample(negativeSample);
		return rule;
	}

	private static RulePriority parsePriority(String value) {
		return Arrays.stream(RulePriority.values())
				.filter(candidate -> candidate.name().equals(StringUtils.trim(value)))
				.findFirst()
				.orElseThrow(() -> new IllegalArgumentException("Choose a priority."));
	}

	private static List<String> parseKeywords(String value) {
		return Arrays.stream(StringUtils.defaultString(value).split(","))
				.map(String::trim)
				.filter(keyword -> !keyword.isEmpty())
				.toList();
	}

	private static Double parseDouble(String value, String field) {
		if (StringUtils.isBlank(value)) {
			return null;
		}
		try {
			return Double.valueOf(value.trim());
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException(field + " must be a number.");
		}
	}

	private static Integer parseInteger(String value, String field) {
		if (StringUtils.isBlank(value)) {
			return null;
		}
		try {
			return Integer.valueOf(value.trim());
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException(field + " must be a whole number.");
		}
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getRuleId() {
		return ruleId;
	}

	public void setRuleId(String ruleId) {
		this.ruleId = ruleId;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getExternalUrl() {
		return externalUrl;
	}

	public void setExternalUrl(String externalUrl) {
		this.externalUrl = externalUrl;
	}

	public String getPriority() {
		return priority;
	}

	public void setPriority(String priority) {
		this.priority = priority;
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

	public String getEntropy() {
		return entropy;
	}

	public void setEntropy(String entropy) {
		this.entropy = entropy;
	}

	public String getSecretGroup() {
		return secretGroup;
	}

	public void setSecretGroup(String secretGroup) {
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
}
