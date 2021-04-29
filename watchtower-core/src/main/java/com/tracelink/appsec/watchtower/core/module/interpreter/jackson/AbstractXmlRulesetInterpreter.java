package com.tracelink.appsec.watchtower.core.module.interpreter.jackson;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.JacksonXmlModule;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;

/**
 * Abstract extension of an {@link AbstractJacksonRulesetInterpreter} for rulesets that are
 * represented as XML. Provides abstracted logic to import and export from an XML format.
 *
 * @author mcool
 */
public abstract class AbstractXmlRulesetInterpreter extends AbstractJacksonRulesetInterpreter {

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected ObjectMapper getObjectMapper() {
		JacksonXmlModule module = new JacksonXmlModule();
		module.setDefaultUseWrapper(false);
		return new XmlMapper(module);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getExtension() {
		return "xml";
	}

}
