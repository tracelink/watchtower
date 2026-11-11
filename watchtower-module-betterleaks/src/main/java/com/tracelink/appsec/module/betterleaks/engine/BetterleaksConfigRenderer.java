package com.tracelink.appsec.module.betterleaks.engine;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistEntry;
import com.tracelink.appsec.module.betterleaks.allowlist.PathGlob;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;

/**
 * Renders the Watchtower-owned Betterleaks config for one scan: the binary's built-in rules plus
 * the allowlist's path entries as {@code [[allowlists]]} tables. Rule-only entries are not
 * rendered - the scanner simply does not enable those rules. The config holds only validated
 * path regexes and rule ids, so it cannot be steered by entry content.
 *
 * @author Watchtower
 */
public final class BetterleaksConfigRenderer {

	/** The config with no allowlist: the binary's built-in default rules. */
	public static final String BASE_CONFIG = "# Written by Watchtower for each scan. Passing it"
			+ " with --config keeps a repository's own\n# .betterleaks.toml or .gitleaks.toml"
			+ " from being used.\n[extend]\nuseDefault = true\n";

	/** Groups entries that apply to every rule. */
	private static final String ALL_RULES = "";

	private BetterleaksConfigRenderer() {
	}

	/**
	 * @param entries the scan's active allowlist entries
	 * @return the TOML config; identical for the same entries in any order
	 * @throws IllegalArgumentException if an entry's path or rule id is malformed
	 */
	public static String render(Collection<BetterleaksAllowlistEntry> entries) {
		return render(entries, List.of());
	}

	/**
	 * @param entries     the scan's active allowlist entries
	 * @param customRules custom rules to define alongside the built-in ones
	 * @return the TOML config
	 * @throws IllegalArgumentException if an entry or custom rule is malformed
	 */
	public static String render(Collection<BetterleaksAllowlistEntry> entries,
			Collection<BetterleaksCustomRuleDto> customRules) {
		StringBuilder toml = new StringBuilder(BASE_CONFIG);
		customRules.stream()
				.sorted(Comparator.comparing(BetterleaksCustomRuleDto::getBetterleaksId))
				.forEach(rule -> appendCustomRule(toml, rule));
		appendAllowlists(toml, entries);
		return toml.toString();
	}

	private static void appendCustomRule(StringBuilder toml, BetterleaksCustomRuleDto rule) {
		List<String> problems = rule.fieldProblems();
		if (!problems.isEmpty()) {
			throw new IllegalArgumentException("Invalid custom rule " + rule.getBetterleaksId()
					+ ": " + String.join(" ", problems));
		}
		toml.append("\n[[rules]]\n")
				.append("id = '").append(rule.getBetterleaksId()).append("'\n")
				.append("description = ").append(basicString(rule.getMessage())).append('\n')
				.append("regex = '''").append(rule.getRegex()).append("'''\n");
		if (!rule.getKeywords().isEmpty()) {
			toml.append("keywords = [")
					.append(rule.getKeywords().stream().map(keyword -> "'" + keyword + "'")
							.collect(Collectors.joining(", ")))
					.append("]\n");
		}
		if (rule.getEntropy() != null) {
			toml.append("entropy = ").append(rule.getEntropy()).append('\n');
		}
		if (rule.getSecretGroup() != null) {
			toml.append("secretGroup = ").append(rule.getSecretGroup()).append('\n');
		}
		if (StringUtils.isNotBlank(rule.getFilter())) {
			toml.append("filter = '''").append(rule.getFilter().trim()).append("'''\n");
		}
	}

	/**
	 * @param value free text
	 * @return a TOML basic string: quotes and backslashes escaped, control characters as
	 *         {@code \}{@code uXXXX}, so it can never end early or span lines
	 */
	private static String basicString(String value) {
		StringBuilder escaped = new StringBuilder("\"");
		for (char c : StringUtils.defaultString(value).toCharArray()) {
			if (c == '"' || c == '\\') {
				escaped.append('\\').append(c);
			} else if (Character.isISOControl(c)) {
				escaped.append(String.format("\\u%04X", (int) c));
			} else {
				escaped.append(c);
			}
		}
		return escaped.append('"').toString();
	}

	private static void appendAllowlists(StringBuilder toml,
			Collection<BetterleaksAllowlistEntry> entries) {
		Map<String, SortedSet<String>> regexesByRule = new TreeMap<>();
		for (BetterleaksAllowlistEntry entry : entries) {
			if (entry.pathGlob() == null) {
				continue;
			}
			String rule = entry.ruleId() == null ? ALL_RULES : entry.ruleId();
			if (!rule.equals(ALL_RULES) && !BetterleaksRuleIds.isValid(rule)) {
				throw new IllegalArgumentException("Invalid Betterleaks rule id: " + rule);
			}
			regexesByRule.computeIfAbsent(rule, key -> new TreeSet<>())
					.add(PathGlob.of(entry.pathGlob()).toRegex());
		}
		regexesByRule.forEach((rule, regexes) -> appendAllowlist(toml, rule, regexes));
	}

	private static void appendAllowlist(StringBuilder toml, String rule,
			SortedSet<String> regexes) {
		boolean allRules = rule.equals(ALL_RULES);
		toml.append("\n[[allowlists]]\n")
				.append("description = 'Watchtower allowlist")
				.append(allRules ? "" : ": " + rule).append("'\n");
		if (!allRules) {
			toml.append("targetRules = ['").append(rule).append("']\n");
		}
		toml.append("paths = [")
				.append(regexes.stream().map(regex -> "'''" + regex + "'''")
						.collect(Collectors.joining(", ")))
				.append("]\n");
	}
}
