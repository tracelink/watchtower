package com.tracelink.appsec.module.checkov.interpreter;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRuleImpexModel;

/**
 * Base class for Checkov Rules. This allows the ruleset to handle both core and special rules
 * 
 * @author csmith
 *
 */
@JsonTypeInfo(
		use = JsonTypeInfo.Id.NAME,
		include = JsonTypeInfo.As.PROPERTY,
		property = "type")
@JsonSubTypes({
	@Type(value = CheckovCoreRuleModel.class, name = "core")
})
public abstract class AbstractCheckovRuleModel extends AbstractRuleImpexModel {

}
