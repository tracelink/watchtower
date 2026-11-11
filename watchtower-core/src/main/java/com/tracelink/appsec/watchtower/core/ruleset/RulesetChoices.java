package com.tracelink.appsec.watchtower.core.ruleset;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetPageService.RulesetSummary;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity;

/**
 * The rulesets a repository or scan can use, grouped for the searchable ruleset picker
 * (UAT walkthrough, 2026-10-16): the default ruleset, the organisation's own rulesets, and the
 * rulesets each scanner provides. Provided rulesets are stored as "Module - name"; the picker shows
 * the name under the scanner's tile. Supporting rulesets are only included by others, so they are
 * not offered, as before.
 */
public record RulesetChoices(Option defaultRuleset, List<Option> own, List<ScannerGroup> scanners) {

	/** One ruleset in the picker: its id, the label shown and the text searched. */
	public record Option(long id, String label, String search) {
	}

	/** The rulesets one scanner provides. */
	public record ScannerGroup(ScannerIdentity scanner, List<Option> rulesets) {
		public String countLabel() {
			return rulesets.size() + (rulesets.size() == 1 ? " ruleset" : " rulesets");
		}
	}

	/** No rulesets: for a page that couldn't read them, so its dialogs still render. */
	public static final RulesetChoices EMPTY = new RulesetChoices(null, List.of(), List.of());

	private static final String PROVIDED_SEPARATOR = " - ";

	public static RulesetChoices of(List<RulesetSummary> summaries) {
		Option defaultRuleset = null;
		List<Option> own = new ArrayList<>();
		Map<String, ScannerGroup> scanners = new LinkedHashMap<>();
		for (RulesetSummary summary : summaries) {
			if (summary.id() == null || summary.isSupporting()) {
				continue;
			}
			String name = summary.name() == null ? "" : summary.name();
			if (summary.isProvided()) {
				int separator = name.indexOf(PROVIDED_SEPARATOR);
				String module = separator > 0 ? name.substring(0, separator) : name;
				String label = separator > 0 ? name.substring(separator + PROVIDED_SEPARATOR.length()) : name;
				ScannerIdentity scanner = ScannerIdentity.of(module);
				scanners.computeIfAbsent(scanner.name(), key -> new ScannerGroup(scanner, new ArrayList<>()))
						.rulesets().add(new Option(summary.id(), label, scanner.name() + " " + label));
				continue;
			}
			Option option = new Option(summary.id(), name, name);
			if (summary.isDefault()) {
				defaultRuleset = option;
			}
			own.add(option);
		}
		List<ScannerGroup> groups = scanners.values().stream()
				.map(group -> new ScannerGroup(group.scanner(), group.rulesets().stream()
						.sorted(Comparator.comparing(Option::label, String.CASE_INSENSITIVE_ORDER)).toList()))
				.sorted(Comparator.comparing(group -> group.scanner().name(), String.CASE_INSENSITIVE_ORDER))
				.toList();
		return new RulesetChoices(defaultRuleset,
				own.stream().sorted(Comparator.comparing(Option::label, String.CASE_INSENSITIVE_ORDER)).toList(),
				groups);
	}

	public int scannerRulesetCount() {
		return scanners.stream().mapToInt(group -> group.rulesets().size()).sum();
	}

	/** The label for a ruleset id, for showing a repository's current ruleset. */
	public String labelOf(Long id) {
		if (id == null) {
			return null;
		}
		for (Option option : own) {
			if (option.id() == id) {
				return option.label();
			}
		}
		for (ScannerGroup group : scanners) {
			for (Option option : group.rulesets()) {
				if (option.id() == id) {
					return group.scanner().name() + " · " + option.label();
				}
			}
		}
		return null;
	}
}
