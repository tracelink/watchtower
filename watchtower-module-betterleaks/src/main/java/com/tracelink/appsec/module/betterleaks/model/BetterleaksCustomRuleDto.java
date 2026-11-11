package com.tracelink.appsec.module.betterleaks.model;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;

/**
 * A Betterleaks rule written in Watchtower, for secret formats the default rules do not know
 * (e.g. internal tokens). It is a set of structured fields that Watchtower renders into the
 * scan config itself - not free-form TOML - so a rule cannot add allowlists, override other
 * rules or make network calls. Every rule carries a sample it must match and one it must not,
 * which the real binary checks before the rule is saved or imported.
 *
 * @author Watchtower
 */
public class BetterleaksCustomRuleDto extends CustomRuleDto implements BetterleaksRuleDto {

	static final int MAX_REGEX_LENGTH = 1000;

	static final int MAX_FILTER_LENGTH = 2000;

	static final int MAX_SAMPLE_LENGTH = 10_000;

	static final int MAX_KEYWORDS = 10;

	static final double MAX_ENTROPY = 8.0;

	static final int MAX_SECRET_GROUP = 20;

	/** Custom ids live in their own namespace, so they can never shadow a provided rule. */
	private static final Pattern ID = Pattern.compile("custom-[a-z0-9][a-z0-9-]{1,60}");

	/**
	 * A reference to CEL's {@code http} extension, however spaced ({@code http .get}). 1.8.1
	 * does not bind it in filters ("unknown name http"), but a later binary might, and a filter
	 * runs against the unredacted match.
	 */
	private static final Pattern NETWORK_CALL = Pattern.compile("(?i)\\bhttp\\s*\\.");

	private static final Pattern KEYWORD = Pattern.compile("[A-Za-z0-9_\\-.:/@]{1,50}");

	/** Ends a TOML multi-line literal string, which the rendered config uses for these fields. */
	private static final String TOML_LITERAL_DELIMITER = "'''";

	private String betterleaksId;

	private String regex;

	private List<String> keywords = new ArrayList<>();

	private Double entropy;

	private Integer secretGroup;

	private String filter;

	private String positiveSample;

	private String negativeSample;

	private int version = 1;

	@Override
	public String getBetterleaksId() {
		return betterleaksId;
	}

	public void setBetterleaksId(String betterleaksId) {
		this.betterleaksId = betterleaksId;
	}

	public String getRegex() {
		return regex;
	}

	public void setRegex(String regex) {
		this.regex = regex;
	}

	public List<String> getKeywords() {
		return keywords;
	}

	public void setKeywords(List<String> keywords) {
		this.keywords = keywords == null ? new ArrayList<>() : new ArrayList<>(keywords);
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

	/**
	 * @return an optional CEL expression; a finding is dropped when it evaluates to true
	 */
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

	public int getVersion() {
		return version;
	}

	public void setVersion(int version) {
		this.version = version;
	}

	@Override
	@JsonIgnore
	public BetterleaksCategory getCategory() {
		return BetterleaksCategory.CUSTOM;
	}

	@Override
	public String getModule() {
		return BetterleaksModule.MODULE_NAME;
	}

	/**
	 * Checks every field that reaches the scan config. The binary check (samples actually match)
	 * happens separately, once these pass.
	 *
	 * @return user-facing problems; empty if the fields are valid
	 */
	@JsonIgnore
	public List<String> fieldProblems() {
		List<String> problems = new ArrayList<>();
		if (betterleaksId == null || !ID.matcher(betterleaksId).matches()) {
			problems.add("The rule id must be 'custom-' followed by lower-case letters, digits"
					+ " and dashes.");
		} else if (!(NAME_PREFIX + betterleaksId).equals(getName())) {
			problems.add("The rule name must be '" + NAME_PREFIX + betterleaksId + "'.");
		}
		if (StringUtils.isBlank(regex)) {
			problems.add("A regex is required.");
		} else {
			checkLiteral(problems, "regex", regex, MAX_REGEX_LENGTH);
		}
		if (filter != null && !filter.isBlank()) {
			checkLiteral(problems, "filter", filter, MAX_FILTER_LENGTH);
			if (NETWORK_CALL.matcher(filter).find()) {
				problems.add("Custom rule filters cannot make network calls.");
			}
		}
		if (keywords.size() > MAX_KEYWORDS) {
			problems.add("At most " + MAX_KEYWORDS + " keywords are allowed.");
		}
		if (keywords.stream().anyMatch(keyword -> keyword == null
				|| !KEYWORD.matcher(keyword).matches())) {
			problems.add("Keywords may use letters, digits and _ - . : / @ only.");
		}
		if (entropy != null && (entropy < 0 || entropy > MAX_ENTROPY)) {
			problems.add("Entropy must be between 0 and " + MAX_ENTROPY + ".");
		}
		if (secretGroup != null && (secretGroup < 0 || secretGroup > MAX_SECRET_GROUP)) {
			problems.add("The secret group must be between 0 and " + MAX_SECRET_GROUP + ".");
		}
		checkSample(problems, "positive", positiveSample);
		checkSample(problems, "negative", negativeSample);
		return problems;
	}

	private static void checkLiteral(List<String> problems, String field, String value,
			int maxLength) {
		if (value.length() > maxLength) {
			problems.add("The " + field + " is limited to " + maxLength + " characters.");
		}
		if (value.contains(TOML_LITERAL_DELIMITER) || value.contains("\n")
				|| value.contains("\r")) {
			problems.add("The " + field + " must be one line and may not contain '''.");
		}
	}

	private static void checkSample(List<String> problems, String which, String sample) {
		if (sample == null || sample.isBlank()) {
			problems.add("A " + which + " sample is required.");
		} else if (sample.length() > MAX_SAMPLE_LENGTH) {
			problems.add("The " + which + " sample is limited to " + MAX_SAMPLE_LENGTH
					+ " characters.");
		}
	}

	@Override
	public BetterleaksRuleEntity toEntity() {
		BetterleaksRuleEntity rule = new BetterleaksRuleEntity();
		rule.setName(getName());
		rule.setAuthor(getAuthor());
		rule.setProvided(false);
		rule.setBetterleaksId(betterleaksId);
		rule.setMessage(getMessage());
		rule.setExternalUrl(getExternalUrl());
		rule.setPriority(getPriority());
		rule.setCategory(BetterleaksCategory.CUSTOM);
		rule.setRegex(regex);
		rule.setKeywords(String.join(",", keywords));
		rule.setEntropy(entropy);
		rule.setSecretGroup(secretGroup);
		rule.setFilter(StringUtils.trimToNull(filter));
		rule.setPositiveSample(positiveSample);
		rule.setNegativeSample(negativeSample);
		rule.setRuleVersion(version);
		return rule;
	}
	@Override
	public String getExternalRuleKey() { return getBetterleaksId(); }

	@Override
	protected RuleRevision executableDefinition() {
		return newDefinition().field("engineRuleKey", getBetterleaksId())
				.field("regex", getRegex()).unordered("keywords", getKeywords())
				.field("entropy", getEntropy() == null ? null : getEntropy().toString())
				.field("secretGroup", getSecretGroup() == null ? null : getSecretGroup().toString())
				.field("filter", StringUtils.trimToNull(getFilter()));
	}
}
