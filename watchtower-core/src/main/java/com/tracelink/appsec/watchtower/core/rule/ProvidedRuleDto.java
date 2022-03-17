package com.tracelink.appsec.watchtower.core.rule;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * The Provided rule extension for {@linkplain RuleDto} objects. This implements some of the
 * {@linkplain RuleDto} abstractions to let concrete subclasses focus on their individual rule data
 * members. Provided rules must be the internally managed system rules that are, besides priority,
 * immutable to users.
 * 
 * @author csmith
 *
 */
public abstract class ProvidedRuleDto extends RuleDto {

	@Override
	@JsonIgnore
	public final String getAuthor() {
		return "system";
	}

	@Override
	@JsonIgnore
	public final RuleDesignation getRuleDesignation() {
		return RuleDesignation.PROVIDED;
	}

}
