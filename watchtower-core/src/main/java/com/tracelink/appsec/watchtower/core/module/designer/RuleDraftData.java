package com.tracelink.appsec.watchtower.core.module.designer;

/**
 * A rule drafted for a person to review in a designer. It is plain text, so a designer can show it without
 * knowing where it came from, and it is not a rule until the person saves it there.
 *
 * @param id                the draft's id, or null before it is stored
 * @param engine            the scanner module the draft is for, lower case (for example {@code regex})
 * @param language          the language the rule scans, when the engine needs one (PMD, JSON format)
 * @param name              the rule name
 * @param message           the finding message
 * @param priority          1 (high) to 6 (informational)
 * @param cwe               the primary CWE, like {@code CWE-89}, or null
 * @param secondaryCwes     comma separated further CWEs, or null
 * @param definition        the rule itself: a regex, an XPath, a JSONPath, an Opengrep rule or an ESLint create function
 * @param fileExtension     the file extension the rule applies to, or null for all files
 * @param vulnerableSnippet a short synthetic example the rule should flag, or null
 * @param safeSnippet       a short synthetic example the rule should not flag, or null
 * @param rationale         why the draft looks like this, in a sentence
 * @param sourceLabel       where the draft came from, for example {@code Coverage gap: CWE-89 · Python}
 */
public record RuleDraftData(String id, String engine, String language, String name, String message, int priority,
		String cwe, String secondaryCwes, String definition, String fileExtension, String vulnerableSnippet,
		String safeSnippet, String rationale, String sourceLabel) {

	/** The same draft with the id it was stored under. */
	public RuleDraftData withId(String newId) {
		return new RuleDraftData(newId, engine, language, name, message, priority, cwe, secondaryCwes, definition,
				fileExtension, vulnerableSnippet, safeSnippet, rationale, sourceLabel);
	}
}
