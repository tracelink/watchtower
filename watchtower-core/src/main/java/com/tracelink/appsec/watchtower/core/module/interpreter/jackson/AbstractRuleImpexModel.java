package com.tracelink.appsec.watchtower.core.module.interpreter.jackson;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * Representation of a rule that facilitates translation to and from structured data.
 * Implementations of this class will be deserialized and serialized in order to import and export
 * rules.
 *
 * @author mcool
 */
public abstract class AbstractRuleImpexModel {
	/**
	 * Converts this rule model object into a data transfer object. Used to convert from a rule
	 * model to a DTO to perform validation of imported rules.
	 *
	 * @return data transfer object representing this rule model
	 */
	protected abstract RuleDto toDto();
}
