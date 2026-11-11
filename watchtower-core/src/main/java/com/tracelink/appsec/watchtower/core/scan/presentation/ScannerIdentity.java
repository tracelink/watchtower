package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.Locale;
import java.util.Map;

/**
 * One scanner's display name, icon and purpose, so the same scanner looks the same everywhere
 * (Home's status panel and its Scanners column). Module names ("AwsSecurityAgent") and recorded
 * execution names ("com...BetterleaksScanner", "PMDScanner", "Json") resolve to one entry.
 */
public record ScannerIdentity(String name, String icon, String purpose) {

	private static final Map<String, ScannerIdentity> KNOWN = Map.of(
			"advisory", new ScannerIdentity("Advisory", "bug_report", "Dependency advisories"),
			"awssecurity", new ScannerIdentity("AWS Security Agent", "cloud", "AWS security review of the repository"),
			"betterleaks", new ScannerIdentity("Betterleaks", "key", "Secrets in any file"),
			"checkov", new ScannerIdentity("Checkov", "layers", "Terraform, Kubernetes, CloudFormation, ARM, Dockerfile"),
			"eslint", new ScannerIdentity("ESLint", "javascript", "JavaScript"),
			"json", new ScannerIdentity("JSON", "data_object", "JSON and YAML documents"),
			"opengrep", new ScannerIdentity("Opengrep", "manage_search", "Python, JavaScript, TypeScript, Java, YAML"),
			"pmd", new ScannerIdentity("PMD", "coffee", "Java, Scala, XML"),
			"regex", new ScannerIdentity("Regex", "pattern", "Text patterns"));

	public static ScannerIdentity of(String rawName) {
		String simple = simpleName(rawName);
		ScannerIdentity known = KNOWN.get(key(simple));
		return known != null ? known : new ScannerIdentity(simple, "radar", "Scanner");
	}

	/** The identity for a name Watchtower knows as a scanner, or empty for any other text. */
	public static java.util.Optional<ScannerIdentity> known(String rawName) {
		return rawName == null || rawName.isBlank() ? java.util.Optional.empty()
				: java.util.Optional.ofNullable(KNOWN.get(key(simpleName(rawName))));
	}

	/**
	 * A rule name without a known scanner prefix: "Betterleaks: private-key" reads "private-key"
	 * next to the Betterleaks tile. Other names, including "Note: …", are returned unchanged.
	 */
	public static String withoutScannerPrefix(String ruleName) {
		if (ruleName == null) {
			return "";
		}
		int separator = ruleName.indexOf(": ");
		return separator > 0 && known(ruleName.substring(0, separator)).isPresent()
				? ruleName.substring(separator + 2) : ruleName;
	}

	/**
	 * A module-provided ruleset's name as people say it: "AwsSecurityAgent - Security review" reads
	 * "AWS Security Agent · Security review". Other names are returned unchanged.
	 */
	public static String readableRulesetName(String rulesetName) {
		if (rulesetName == null) {
			return "";
		}
		int separator = rulesetName.indexOf(" - ");
		if (separator <= 0) {
			return rulesetName;
		}
		return known(rulesetName.substring(0, separator))
				.map(scanner -> scanner.name() + " · " + rulesetName.substring(separator + 3))
				.orElse(rulesetName);
	}

	/**
	 * The scanner that provides a ruleset ("AwsSecurityAgent - Security review" is AWS Security
	 * Agent's), so lists can draw its tile beside the readable name; null for other rulesets.
	 */
	public static ScannerIdentity rulesetScanner(String rulesetName) {
		int separator = rulesetName == null ? -1 : rulesetName.indexOf(" - ");
		return separator <= 0 ? null : known(rulesetName.substring(0, separator)).orElse(null);
	}

	/** The lookup key: lower-case letters and digits, without a "Scanner" or "Agent" suffix. */
	static String key(String simpleName) {
		String key = simpleName.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
		for (String suffix : new String[] {"scanner", "agent"}) {
			if (key.endsWith(suffix) && key.length() > suffix.length()) {
				key = key.substring(0, key.length() - suffix.length());
			}
		}
		return key;
	}

	private static String simpleName(String rawName) {
		if (rawName == null || rawName.isBlank()) {
			return "Unknown scanner";
		}
		String trimmed = rawName.trim();
		return trimmed.substring(trimmed.lastIndexOf('.') + 1);
	}
}
