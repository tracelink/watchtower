package com.tracelink.appsec.module.regex.xml;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRulesetImpexModel;

import java.util.Set;

/**
 * Implementation of an {@linkplain AbstractRulesetImpexModel} that represents a ruleset
 * containing only regex rules. Rules in this ruleset must be of type
 * {@linkplain RegexRuleXmlModel}. Used to convert regex rules into XML for
 * scans and to import regex rulesets.
 *
 * @author mcool
 */
@JacksonXmlRootElement(localName = "ruleset")
public class RegexRulesetXmlModel extends AbstractRulesetImpexModel {
	@JacksonXmlProperty(isAttribute = true)
	private String name;
	@JacksonXmlProperty
	private String description;
	@JacksonXmlProperty(localName = "rule")
	private Set<RegexRuleXmlModel> rules;

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
	public Set<RegexRuleXmlModel> getRules() {
		return rules;
	}

	public void setRules(Set<RegexRuleXmlModel> rules) {
		this.rules = rules;
	}
}
