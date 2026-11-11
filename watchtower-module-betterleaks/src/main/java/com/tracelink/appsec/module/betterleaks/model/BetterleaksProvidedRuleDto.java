package com.tracelink.appsec.module.betterleaks.model;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.watchtower.core.rule.ProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;

/**
 * A rule from the pinned Betterleaks default config. The engine runs it by its Betterleaks id;
 * the Watchtower name ({@code "Betterleaks: <id>"}) is what findings and rulesets refer to.
 *
 * @author Watchtower
 */
public class BetterleaksProvidedRuleDto extends ProvidedRuleDto implements BetterleaksRuleDto {

	private String betterleaksId;

	private String message;

	private String externalUrl;

	private BetterleaksCategory category;

	private String confidence;

	@Override
	public String getBetterleaksId() {
		return betterleaksId;
	}

	public void setBetterleaksId(String betterleaksId) {
		this.betterleaksId = betterleaksId;
	}

	@Override
	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	@Override
	public String getExternalUrl() {
		return externalUrl;
	}

	public void setExternalUrl(String externalUrl) {
		this.externalUrl = externalUrl;
	}

	@Override
	public BetterleaksCategory getCategory() {
		return category;
	}

	public void setCategory(BetterleaksCategory category) {
		this.category = category;
	}

	/**
	 * @return Betterleaks' own confidence in the rule ({@code low}, {@code medium}, {@code high})
	 */
	public String getConfidence() {
		return confidence;
	}

	public void setConfidence(String confidence) {
		this.confidence = confidence;
	}

	@Override
	public String getModule() {
		return BetterleaksModule.MODULE_NAME;
	}

	@Override
	public BetterleaksRuleEntity toEntity() {
		BetterleaksRuleEntity rule = new BetterleaksRuleEntity();
		rule.setName(getName());
		rule.setAuthor(getAuthor());
		rule.setProvided(true);
		rule.setBetterleaksId(getBetterleaksId());
		rule.setMessage(getMessage());
		rule.setExternalUrl(getExternalUrl());
		rule.setPriority(getPriority());
		rule.setCategory(getCategory());
		rule.setConfidence(getConfidence());
		return rule;
	}
	@Override
	public String getExternalRuleKey() { return getBetterleaksId(); }

	@Override
	protected RuleRevision executableDefinition() {
		return newDefinition().field("engineRuleKey", getBetterleaksId());
	}
}
