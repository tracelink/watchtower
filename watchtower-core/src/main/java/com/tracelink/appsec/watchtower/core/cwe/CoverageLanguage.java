package com.tracelink.appsec.watchtower.core.cwe;

import java.util.Locale;
import java.util.Set;

/** The language columns of the coverage table. OTHER only shows when some rule actually covers it. */
public enum CoverageLanguage {
	JAVA("Java / Spring"), PYTHON("Python"), JAVASCRIPT("JS / TS"), OTHER("Other");

	private static final Set<String> JAVA_NAMES = Set.of("java", "kotlin", "scala", "jsp");
	private static final Set<String> JAVASCRIPT_NAMES = Set.of("javascript", "typescript", "js", "ts", "jsx", "tsx", "ecmascript",
			"node", "nodejs");
	private final String label;

	CoverageLanguage(String label) {
		this.label = label;
	}

	public String label() {
		return label;
	}

	/** The column a language name belongs to; anything unrecognised is OTHER. */
	public static CoverageLanguage of(String language) {
		String name = language == null ? "" : language.strip().toLowerCase(Locale.ROOT);
		if (JAVA_NAMES.contains(name)) {
			return JAVA;
		}
		if (name.equals("python") || name.equals("py")) {
			return PYTHON;
		}
		return JAVASCRIPT_NAMES.contains(name) ? JAVASCRIPT : OTHER;
	}
}
