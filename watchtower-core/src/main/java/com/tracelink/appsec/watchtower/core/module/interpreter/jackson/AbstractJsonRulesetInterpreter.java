package com.tracelink.appsec.watchtower.core.module.interpreter.jackson;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Abstract extension of an {@link AbstractJacksonRulesetInterpreter} for rulesets that are
 * represented as JSON. Provides abstracted logic to import and export from a JSON format.
 *
 * @author csmith
 */
public abstract class AbstractJsonRulesetInterpreter extends AbstractJacksonRulesetInterpreter {

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected ObjectMapper getObjectMapper() {
		return new ObjectMapper();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getExtension() {
		return "json";
	}
}


