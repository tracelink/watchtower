package com.tracelink.appsec.module.pmd.service;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public enum PMDLanguageSupport {
	JAVA("Java", ""),
	ECMA("Ecmascript", ""),
	SCALA("Scala", ""),
	XML("XML", "");
	private final String languageName;
	private final String[] coreRulesetLocations;

	private PMDLanguageSupport(String languageName, String... coreRulesetLocations) {
		this.languageName = languageName;
		this.coreRulesetLocations = coreRulesetLocations;
	}

	public String getLanguageName() {
		return languageName;
	}

	public String[] getCoreRulesetLocations() {
		return coreRulesetLocations;
	}

	public String toString() {
		return languageName;
	}

	public static List<String> getSupportedLanguageNames() {
		return Arrays.stream(PMDLanguageSupport.values())
				.map(PMDLanguageSupport::toString)
				.collect(Collectors.toList());
	}
}
