package com.tracelink.appsec.module.pmd.xml;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRulesetImpexModel;

import java.util.Set;

/**
 * Implementation of an {@linkplain AbstractRulesetImpexModel} that represents a ruleset
 * containing only PMD rules. Rules in this ruleset must be of type
 * {@linkplain PMDRuleXmlModel}. Contains attributes and elements specific to
 * PMD. Used to convert PMD rules into XML for scans and to import PMD rulesets.
 *
 * @author mcool
 */
@JacksonXmlRootElement(localName = "ruleset")
public class PMDRulesetXmlModel extends AbstractRulesetImpexModel {
	@JacksonXmlProperty(isAttribute = true)
	private String name;
	@JacksonXmlProperty(isAttribute = true)
	private String xmlns = "http://pmd.sourceforge.net/ruleset/2.0.0";
	@JacksonXmlProperty(namespace = "xmlns", localName = "xsi", isAttribute = true)
	private String xmlnsXsi = "http://www.w3.org/2001/XMLSchema-instance";
	@JacksonXmlProperty(namespace = "xsi", localName = "schemaLocation", isAttribute = true)
	private String xsiSchemaLocation = "http://pmd.sourceforge.net/ruleset/2.0.0 https://pmd.sourceforge.io/ruleset_2_0_0.xsd";
	private String description;
	@JacksonXmlProperty(localName = "rule")
	private Set<PMDRuleXmlModel> rules;

	public String getXmlns() {
		return xmlns;
	}

	public void setXmlns(String xmlns) {
		this.xmlns = xmlns;
	}

	public String getXmlnsXsi() {
		return xmlnsXsi;
	}

	public void setXmlnsXsi(String xmlnsXsi) {
		this.xmlnsXsi = xmlnsXsi;
	}

	public String getXsiSchemaLocation() {
		return xsiSchemaLocation;
	}

	public void setXsiSchemaLocation(String xsiSchemaLocation) {
		this.xsiSchemaLocation = xsiSchemaLocation;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name.trim();
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
	public Set<PMDRuleXmlModel> getRules() {
		return rules;
	}

	public void setRules(Set<PMDRuleXmlModel> rules) {
		this.rules = rules;
	}
}
