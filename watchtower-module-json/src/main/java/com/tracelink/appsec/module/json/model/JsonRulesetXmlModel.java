package com.tracelink.appsec.module.json.model;

import java.util.Set;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRulesetImpexModel;

/**
 * Implementation of an {@linkplain AbstractRulesetImpexModel} that represents a ruleset containing
 * only json-based rules. Rules in this ruleset must be of type {@linkplain JsonRuleXmlModel}. Used
 * to convert json rules into XML for scans and to import json path rulesets.
 *
 * @author csmith
 */
@JacksonXmlRootElement(localName = "ruleset")
public class JsonRulesetXmlModel extends AbstractRulesetImpexModel {
	@JacksonXmlProperty(isAttribute = true)
	private String name;
	@JacksonXmlProperty
	private String description;
	@JacksonXmlProperty(localName = "rule")
	private Set<JsonRuleXmlModel> rules;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description.trim();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Set<JsonRuleXmlModel> getRules() {
		return rules;
	}

	public void setRules(Set<JsonRuleXmlModel> rules) {
		this.rules = rules;
	}
}
