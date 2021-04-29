package com.tracelink.appsec.module.pmd.xml;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlCData;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

/**
 * Represents a property of a PMD rule. The value element can contain XPath
 * expressions.
 *
 * @author mcool
 */
public class Property {
	@JacksonXmlProperty(isAttribute = true)
	private String name = "xpath";
	@JacksonXmlCData
	private String value;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value.trim();
	}
}
