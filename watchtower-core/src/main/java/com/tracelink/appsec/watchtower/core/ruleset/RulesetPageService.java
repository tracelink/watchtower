package com.tracelink.appsec.watchtower.core.ruleset;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignation;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleState;
import com.tracelink.appsec.watchtower.core.scan.presentation.RuleMessageText;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity;

/**
 * Read side of the Rulesets page (UAT walkthrough, 2026-10-16). The page used to build a DTO for
 * every ruleset with every rule and every inherited ruleset (each collection is EAGER), which took
 * over 30 seconds with 1,172 rules. Here rulesets are read as scalar rows, the included rulesets
 * from the ruleset-to-ruleset links, and the rules one page at a time with count queries for the
 * summary. Retired rules are left out everywhere, as they never run.
 */
@Service
@Transactional(readOnly = true)
public class RulesetPageService {
	public static final List<String> SCOPES = List.of("all", "own", "included");
	public static final List<Integer> PAGE_SIZES = List.of(25, 50, 100);
	public static final String ALL = "all";

	private final LedgerRepository records;
	private final RuleService rules;

	public RulesetPageService(LedgerRepository records, RuleService rules) {
		this.records = records;
		this.rules = rules;
	}

	/** One ruleset without its rules: enough for the picker, the dialogs and the header. */
	public record RulesetSummary(Long id, String name, String description, RulesetDesignation designation,
			RulePriority blockingLevel) {
		public boolean isDefault() {
			return designation == RulesetDesignation.DEFAULT;
		}

		public boolean isPrimary() {
			return designation == RulesetDesignation.PRIMARY || isDefault();
		}

		public boolean isSupporting() {
			return designation == RulesetDesignation.SUPPORTING;
		}

		public boolean isProvided() {
			return designation == RulesetDesignation.PROVIDED;
		}
	}

	/** One rule row: scanner tile, readable name and message, severity, and where it comes from. */
	public record RuleRow(long id, String name, ScannerIdentity scanner, String module, RulePriority priority,
			String message, String externalUrl, String from) {
		public boolean isOwn() {
			return from == null;
		}

		public String severityClass() {
			return "wt-sev wt-sev-" + (priority == null ? 6 : priority.getPriority());
		}

		public String severityName() {
			return priority == null ? "Unknown" : priority.getName();
		}
	}

	/** A scanner in this ruleset and how many of its rules it brings. */
	public record ScannerCount(String key, String module, ScannerIdentity scanner, long rules) {
	}

	/** Filters for the rule table, validated once. */
	public record Filter(String scope, String scanner, String severity, int page, int pageSize) {
		public Filter {
			scope = scope == null || scope.isBlank() ? ALL : scope;
			scanner = scanner == null || scanner.isBlank() ? ALL : scanner.toLowerCase(Locale.ROOT);
			severity = severity == null || severity.isBlank() ? ALL : severity;
			if (!SCOPES.contains(scope)) {
				throw new IllegalArgumentException("Unknown rule scope");
			}
			if (!ALL.equals(severity) && priority(severity) == null) {
				throw new IllegalArgumentException("Unknown severity");
			}
			if (!scanner.matches("[a-z0-9_-]{1,64}")) {
				throw new IllegalArgumentException("Unknown scanner");
			}
			if (page < 0 || !PAGE_SIZES.contains(pageSize) || (long) page * pageSize > Integer.MAX_VALUE) {
				throw new IllegalArgumentException("Choose a valid page");
			}
		}

		public RulePriority priority() {
			return ALL.equals(severity) ? null : priority(severity);
		}

		private static RulePriority priority(String name) {
			for (RulePriority priority : RulePriority.values()) {
				if (priority.name().equals(name)) {
					return priority;
				}
			}
			return null;
		}
	}

	/** Everything the page shows for one ruleset. */
	public record RulesetView(RulesetSummary ruleset, List<RulesetSummary> included, Set<Long> directlyIncluded,
			Set<Long> ownRuleIds, long allCount, long ownCount, long includedCount, List<ScannerCount> scanners,
			boolean secretsMayNotBlock, PagedResult<RuleRow> rows) {
	}

	/** Every ruleset, ordered as before: designation (default first), then name. */
	public List<RulesetSummary> summaries() {
		List<RulesetSummary> summaries = new ArrayList<>();
		for (var row : records.maps("SELECT s.id AS id,s.name AS name,s.description AS description,"
				+ "s.designation AS designation,s.blockingLevel AS blocking FROM RulesetEntity s", 0, Integer.MAX_VALUE)) {
			summaries.add(new RulesetSummary((Long) row.get("id"), (String) row.get("name"),
					(String) row.get("description"), (RulesetDesignation) row.get("designation"),
					(RulePriority) row.get("blocking")));
		}
		summaries.sort(Comparator.comparing(RulesetSummary::designation, Comparator.nullsLast(Comparator.naturalOrder()))
				.thenComparing(RulesetSummary::name, Comparator.nullsLast(Comparator.naturalOrder())));
		return List.copyOf(summaries);
	}

	public static Optional<RulesetSummary> defaultOf(List<RulesetSummary> summaries) {
		return summaries.stream().filter(RulesetSummary::isDefault).findFirst();
	}

	/**
	 * The page for one ruleset. {@code sensitiveModule} marks secrets scanners, for the "Secrets may
	 * not block" chip: their rules start at Medium, so a ruleset blocking only above that lets them
	 * through.
	 */
	public RulesetView view(RulesetSummary ruleset, List<RulesetSummary> summaries, Filter filter,
			Predicate<String> sensitiveModule) {
		Map<Long, List<Long>> links = links();
		Set<Long> closure = closure(ruleset.id(), links);
		Map<Long, RulesetSummary> byId = new HashMap<>();
		summaries.forEach(summary -> byId.put(summary.id(), summary));
		List<RulesetSummary> included = closure.stream().map(byId::get).filter(Objects::nonNull)
				.sorted(Comparator.comparing(RulesetSummary::name)).toList();

		Set<Long> ownRuleIds = new LinkedHashSet<>(records.list(Long.class,
				"SELECT r.id FROM RulesetEntity s JOIN s.rules r WHERE s.id=?1", 0, Integer.MAX_VALUE, ruleset.id()));
		List<Long> effective = records.list(Long.class, "SELECT DISTINCT r.id FROM RulesetEntity s JOIN s.rules r"
				+ " WHERE s.id IN ?1 AND r.stewardship.state<>?2", 0, Integer.MAX_VALUE, withSelf(ruleset.id(), closure),
				RuleState.RETIRED);
		long ownCount = count(scope("own", ruleset.id(), closure, new Filter("own", ALL, ALL, 0, 25)));
		long allCount = effective.size();

		List<ScannerCount> scanners = new ArrayList<>();
		rules.countModulesOf(effective).forEach((module, count) -> scanners.add(
				new ScannerCount(module.toLowerCase(Locale.ROOT), module, ScannerIdentity.of(module), count)));
		RulePriority blocking = ruleset.blockingLevel();
		boolean blocksMedium = blocking != null && RulePriority.MEDIUM.compareTo(blocking) <= 0;
		boolean secretsMayNotBlock = !blocksMedium
				&& scanners.stream().anyMatch(scanner -> sensitiveModule.test(scanner.module()));

		Query query = scope(filter.scope(), ruleset.id(), closure, filter);
		long total = count(query);
		return new RulesetView(ruleset, included, Set.copyOf(links.getOrDefault(ruleset.id(), List.of())),
				ownRuleIds, allCount, ownCount, allCount - ownCount, List.copyOf(scanners), secretsMayNotBlock,
				new PagedResult<>(rows(query, filter), filter.page(), filter.pageSize(), total,
						(int) Math.ceil((double) total / filter.pageSize())));
	}

	/** One rule in the "Rules in …" dialog: tick state from the ruleset, scanner tile, custom or provided. */
	public record RuleChoice(long id, String name, boolean custom, String scanner, String scannerName,
			String icon, boolean retired, boolean selected) {
	}

	/**
	 * Every rule for the "Rules in …" dialog, read as scalars (a rule entity drags in its rulesets and
	 * their rules), ticked where the ruleset itself holds it. Retired rules are listed too, so saving
	 * never silently drops one the ruleset still holds.
	 */
	public List<RuleChoice> ruleChoices(long rulesetId) {
		Set<Long> own = new LinkedHashSet<>(records.list(Long.class,
				"SELECT r.id FROM RulesetEntity s JOIN s.rules r WHERE s.id=?1", 0, Integer.MAX_VALUE, rulesetId));
		List<RuleChoice> choices = new ArrayList<>();
		var mixedDesignations = rules.designationsOfMixedRules();
		for (var row : records.maps("SELECT r.id AS id,r.name AS name,TYPE(r) AS type,r.stewardship.state AS state"
				+ " FROM RuleEntity r ORDER BY r.name,r.id", 0, Integer.MAX_VALUE)) {
			Class<?> type = (Class<?>) row.get("type");
			String module = rules.moduleOfType(type);
			ScannerIdentity scanner = ScannerIdentity.of(module);
			long id = (Long) row.get("id");
			choices.add(new RuleChoice(id, ScannerIdentity.withoutScannerPrefix((String) row.get("name")),
					mixedDesignations.getOrDefault(id, rules.designationOfType(type)) != RuleDesignation.PROVIDED,
					module.toLowerCase(Locale.ROOT), scanner.name(), scanner.icon(), row.get("state") == RuleState.RETIRED,
					own.contains(id)));
		}
		return List.copyOf(choices);
	}

	/**
	 * How many rules each ruleset runs: its own plus those of every ruleset it includes, retired
	 * rules left out (as on the page's rule count). One scalar query of ruleset-to-rule links.
	 */
	public Map<Long, Integer> ruleCounts(List<RulesetSummary> summaries) {
		Map<Long, Set<Long>> ownRules = new HashMap<>();
		for (var row : records.maps("SELECT s.id AS ruleset,r.id AS rule FROM RulesetEntity s JOIN s.rules r"
				+ " WHERE r.stewardship.state<>?1", 0, Integer.MAX_VALUE, RuleState.RETIRED)) {
			ownRules.computeIfAbsent((Long) row.get("ruleset"), id -> new LinkedHashSet<>()).add((Long) row.get("rule"));
		}
		Map<Long, List<Long>> links = links();
		Map<Long, Integer> counts = new HashMap<>();
		for (var summary : summaries) {
			Set<Long> effective = new LinkedHashSet<>(ownRules.getOrDefault(summary.id(), Set.of()));
			closure(summary.id(), links).forEach(id -> effective.addAll(ownRules.getOrDefault(id, Set.of())));
			counts.put(summary.id(), effective.size());
		}
		return Map.copyOf(counts);
	}

	/** The scanners that own rules, for validating the Scanner filter. */
	public Map<String, ScannerIdentity> knownScanners() {
		Map<String, ScannerIdentity> known = new LinkedHashMap<>();
		rules.countRulesByModule().keySet().stream().sorted().forEach(module -> known.put(module, ScannerIdentity.of(module)));
		return known;
	}

	// --- Queries: fixed fragments only; every value is bound. ---

	private record Query(String from, Object[] args) {
	}

	private Query scope(String scope, long rulesetId, Set<Long> closure, Filter filter) {
		List<Object> args = new ArrayList<>();
		args.add(rulesetId);
		String sources = switch (scope) {
			case "own" -> "s.id=?1";
			case "included" -> {
				args.add(closure.isEmpty() ? List.of(-1L) : List.copyOf(closure));
				yield "s.id IN ?2 AND r.id NOT IN (SELECT r2.id FROM RulesetEntity s2 JOIN s2.rules r2 WHERE s2.id=?1)";
			}
			default -> {
				args.add(closure.isEmpty() ? List.of(-1L) : List.copyOf(closure));
				yield "(s.id=?1 OR s.id IN ?2)";
			}
		};
		StringBuilder from = new StringBuilder("FROM RulesetEntity s JOIN s.rules r WHERE ").append(sources);
		args.add(RuleState.RETIRED);
		from.append(" AND r.stewardship.state<>?").append(args.size());
		if (!ALL.equals(filter.scanner())) {
			List<Class<? extends RuleEntity>> types = rules.ruleTypesOfModule(filter.scanner());
			if (types.isEmpty()) {
				from.append(" AND 1=0");
			} else {
				args.add(types);
				from.append(" AND TYPE(r) IN ?").append(args.size());
			}
		}
		if (filter.priority() != null) {
			args.add(filter.priority());
			from.append(" AND r.priority=?").append(args.size());
		}
		return new Query(from.toString(), args.toArray());
	}

	private long count(Query query) {
		return records.scalar(Long.class, "SELECT COUNT(DISTINCT r.id) " + query.from(), query.args());
	}

	/** One page of rule ids, then those rules: the source is the ruleset itself or an included one. */
	private List<RuleRow> rows(Query query, Filter filter) {
		var page = records.maps("SELECT r.id AS id,r.name AS name,MIN(CASE WHEN s.id=?1 THEN '' ELSE s.name END) AS source "
				+ query.from() + " GROUP BY r.id,r.name ORDER BY r.name,r.id", filter.page() * filter.pageSize(),
				filter.pageSize(), query.args());
		if (page.isEmpty()) {
			return List.of();
		}
		List<Long> ids = page.stream().map(row -> (Long) row.get("id")).toList();
		// Scalars only: a RuleEntity eagerly loads its rulesets, and each ruleset all of its rules,
		// so loading even one page of rule entities would pull in most of the rule graph.
		Map<Long, Map<String, Object>> details = new HashMap<>();
		for (var row : records.maps("SELECT r.id AS id,r.message AS message,r.externalUrl AS url,r.priority AS priority,"
				+ "TYPE(r) AS type FROM RuleEntity r WHERE r.id IN ?1", 0, ids.size(), ids)) {
			details.put((Long) row.get("id"), row);
		}
		List<RuleRow> rows = new ArrayList<>();
		for (var row : page) {
			Map<String, Object> detail = details.get((Long) row.get("id"));
			if (detail == null) {
				continue;
			}
			String source = (String) row.get("source");
			String module = rules.moduleOfType((Class<?>) detail.get("type"));
			rows.add(new RuleRow((Long) row.get("id"), ScannerIdentity.withoutScannerPrefix((String) row.get("name")),
					ScannerIdentity.of(module), module, (RulePriority) detail.get("priority"),
					RuleMessageText.readable((String) detail.get("message")), (String) detail.get("url"),
					source == null || source.isEmpty() ? null : source));
		}
		return rows;
	}

	/** Ruleset → directly included rulesets, read as ids only. */
	private Map<Long, List<Long>> links() {
		Map<Long, List<Long>> links = new HashMap<>();
		for (var row : records.maps("SELECT s.id AS parent,i.id AS child FROM RulesetEntity s JOIN s.rulesets i", 0,
				Integer.MAX_VALUE)) {
			links.computeIfAbsent((Long) row.get("parent"), id -> new ArrayList<>()).add((Long) row.get("child"));
		}
		return links;
	}

	/** Every ruleset reachable through includes, not counting the ruleset itself. */
	static Set<Long> closure(long rulesetId, Map<Long, List<Long>> links) {
		Set<Long> seen = new LinkedHashSet<>();
		Deque<Long> next = new ArrayDeque<>(links.getOrDefault(rulesetId, List.of()));
		while (!next.isEmpty()) {
			Long id = next.pop();
			if (id != rulesetId && seen.add(id)) {
				next.addAll(links.getOrDefault(id, List.of()));
			}
		}
		return seen;
	}

	private static List<Long> withSelf(long rulesetId, Set<Long> closure) {
		List<Long> ids = new ArrayList<>(closure);
		ids.add(rulesetId);
		return ids;
	}

}
