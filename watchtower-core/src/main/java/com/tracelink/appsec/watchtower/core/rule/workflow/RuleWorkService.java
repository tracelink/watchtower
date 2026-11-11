package com.tracelink.appsec.watchtower.core.rule.workflow;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Locale;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.persistence.RuleCandidateEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleState;
import com.tracelink.appsec.watchtower.core.rule.RuleStewardship;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity;

/**
 * The rule work overview (UAT #18): five queues read from existing rules, metrics, finding
 * feedback, reviews and candidates. Nothing here creates task records; each row links to the
 * page where the work is done. Counts use the current rule revision and the same thresholds as
 * the rule health page, so a rule listed as noisy here shows the same evidence there.
 */
@Service
@Transactional(readOnly = true)
public class RuleWorkService {
	public static final List<String> QUEUES = List.of("review", "investigate", "reviews", "candidates", "setup");
	public static final Set<String> SCAN_QUEUES = Set.of("review", "investigate");
	public static final Set<String> MODIFY_QUEUES = Set.of("candidates");
	public static final List<String> GAPS = List.of("all", "owner", "cwe", "nomatches");
	public static final List<Integer> WINDOWS = List.of(7, 30, 90);
	public static final String ALL = "all";
	private static final DateTimeFormatter DUE = DateTimeFormatter.ofPattern("dd MMM yyyy", Locale.ENGLISH);

	private final LedgerRepository records;
	private final RuleHealthService health;
	private final RuleWorkLinks links;
	private final RuleService rules;
	private final RuleWorkQueries queries;

	public RuleWorkService(LedgerRepository records, RuleHealthService health, RuleWorkLinks links, RuleService rules) {
		this.records = records;
		this.health = health;
		this.links = links;
		this.rules = rules;
		this.queries = new RuleWorkQueries(records, health, rules);
	}

	/** The scanners that own rules, for the Setup gaps scanner filter: module key to scanner. */
	public Map<String, ScannerIdentity> scanners() {
		Map<String, ScannerIdentity> scanners = new java.util.TreeMap<>();
		rules.countRulesByModule().keySet().forEach(module -> scanners.put(module, ScannerIdentity.of(module)));
		return scanners;
	}

	/**
	 * One unit of work, ready to draw: the rule (name without a scanner prefix, plus its scanner),
	 * a state chip or a meter for why it is listed, evidence chips, and the next action (null when
	 * the viewer may not do it). {@code why} and {@code evidence} keep the full sentences for hover.
	 */
	public record WorkItem(long ruleId, String ruleName, ScannerIdentity scanner, String owner, LocalDate reviewBy,
			String why, String evidence, Chip state, Meter meter, List<Chip> chips, String nextAction,
			String actionIcon, String actionUrl, Long updatedAt) {
		public WorkItem {
			chips = List.copyOf(chips);
		}
	}

	/**
	 * The plain values a work row needs from a rule. Rows are read as values, never as rule
	 * entities: loading a rule eagerly pulls in its rulesets and their rules, which made the
	 * Rulesets page take over 30 seconds (UAT walkthrough, 2026-10-16).
	 */
	record RuleRow(long id, String name, String module, String owner, LocalDate reviewBy, String cwe,
			String revision, boolean notSecurity) {
	}

	/** A small labelled chip; tone is ok, warn, bad, info, shadow or empty for neutral. */
	public record Chip(String text, String icon, String tone, String tip) {
	}

	/** Progress toward a threshold, e.g. "1 of 6 reviewed"; {@code alarm} draws it red. */
	public record Meter(long done, long of, String text, String tip, boolean alarm) {
		public long percent() {
			return of <= 0 ? 0 : Math.min(100, Math.round(100.0 * done / of));
		}
	}

	/**
	 * Filters and the viewer's access, validated once so counts and rows always agree.
	 * {@code exactOwner} serves "Assigned to me": "bob" must not also match "bobby".
	 */
	public record Filter(String search, String owner, boolean exactOwner, int days, String gap, boolean canSeeScans,
			boolean canModify, String scanner) {
		public Filter(String search, String owner, boolean exactOwner, int days, String gap, boolean canSeeScans,
				boolean canModify) {
			this(search, owner, exactOwner, days, gap, canSeeScans, canModify, ALL);
		}

		public Filter {
			if (!WINDOWS.contains(days)) {
				throw new IllegalArgumentException("Choose a 7, 30 or 90 day window");
			}
			if (!GAPS.contains(gap)) {
				throw new IllegalArgumentException("Unknown setup gap");
			}
			RuleReviewWorkspace.pattern(search);
			RuleReviewWorkspace.pattern(owner);
			scanner = scanner == null || scanner.isBlank() ? ALL : scanner.toLowerCase(Locale.ROOT);
			if (!scanner.matches("[a-z0-9_-]{1,64}")) {
				throw new IllegalArgumentException("Unknown scanner");
			}
		}

		public boolean allScanners() {
			return ALL.equals(scanner);
		}

		public boolean canSee(String queue) {
			return (canSeeScans || !SCAN_QUEUES.contains(queue)) && (canModify || !MODIFY_QUEUES.contains(queue));
		}

		/** Tab links open each queue on all setup gaps, so its count uses the same scope. */
		Filter forCount(String queue) {
			return "setup".equals(queue) ? new Filter(search, owner, exactOwner, days, ALL, canSeeScans, canModify, ALL)
					: this;
		}
	}

	/** Rejects an unknown queue or page bounds before any query runs. */
	public static void validate(String queue, int page, int size) {
		if (!QUEUES.contains(queue)) {
			throw new IllegalArgumentException("Unknown work queue");
		}
		RuleReviewWorkspace.bounds(page, size);
	}

	/**
	 * Item count per queue; null where the viewer may not see that queue. The open queue's total is
	 * passed in so its (most expensive) count is not run twice.
	 */
	public Map<String, Long> counts(Filter filter, String openQueue, long openTotal) {
		Map<String, Long> counts = new LinkedHashMap<>();
		for (String queue : QUEUES) {
			if (!filter.canSee(queue)) {
				counts.put(queue, null);
			} else if (queue.equals(openQueue) && !"setup".equals(queue)) {
				counts.put(queue, openTotal);
			} else {
				counts.put(queue, queries.count(queue, filter.forCount(queue)));
			}
		}
		return counts;
	}

	public PagedResult<WorkItem> queue(String queue, Filter filter, int page, int size) {
		validate(queue, page, size);
		if (!filter.canSee(queue)) {
			return RuleReviewWorkspace.page(List.of(), page, size, 0);
		}
		RuleWorkQueries.Rows found = queries.page(queue, filter, page * size, size);
		List<Map<String, Object>> rows = found.rows();
		long total = found.total();
		Map<Class<?>, String> modules = new java.util.HashMap<>();
		List<RuleRow> ruleRows = rows.stream().map(row -> ruleRow(row, modules)).toList();
		List<WorkItem> items = switch (queue) {
			case "review", "investigate" -> scanItems(queue, ruleRows, filter);
			case "reviews" -> ruleRows.stream().map(RuleWorkService::reviewsItem).toList();
			case "candidates" -> java.util.stream.IntStream.range(0, rows.size())
					.mapToObj(i -> candidateItem((RuleCandidateEntity) rows.get(i).get("candidate"), ruleRows.get(i)))
					.toList();
			default -> ruleRows.stream().map(row -> setupItem(row, filter)).toList();
		};
		return RuleReviewWorkspace.page(items, page, size, total);
	}

	private RuleRow ruleRow(Map<String, Object> row, Map<Class<?>, String> modules) {
		Class<?> type = (Class<?>) row.get("rule_type");
		String module = modules.computeIfAbsent(type, rules::moduleOfType);
		return new RuleRow((Long) row.get("rule_id"), (String) row.get("rule_name"), module, (String) row.get("owner"),
				(LocalDate) row.get("review_by"), (String) row.get("cwe"), (String) row.get("revision"),
				RuleStewardship.NOT_SECURITY.equals(row.get("security_relevance")));
	}

	static long since(int days) {
		return LocalDate.now(ZoneOffset.UTC).minusDays(days - 1L).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
	}

	// --- Row mapping ---

	/** Numbers for the page's rules only: two grouped queries instead of per-row subqueries. */
	private List<WorkItem> scanItems(String queue, List<RuleRow> pageRules, Filter filter) {
		if (pageRules.isEmpty()) {
			return List.of();
		}
		List<Long> ids = pageRules.stream().map(RuleRow::id).toList();
		long since = since(filter.days());
		Map<Long, Long> matches = new LinkedHashMap<>();
		for (var row : queries.matchesFor(ids, since)) {
			if (current(pageRules, row)) {
				matches.put((Long) row.get("rule_id"), ((Number) row.get("n")).longValue());
			}
		}
		Map<Long, Map<String, Long>> judgments = new LinkedHashMap<>();
		for (var row : queries.judgmentsFor(ids, since)) {
			if (current(pageRules, row)) {
				judgments.computeIfAbsent((Long) row.get("rule_id"), id -> new LinkedHashMap<>())
						.put((String) row.get("judgment"), ((Number) row.get("n")).longValue());
			}
		}
		Map<Long, List<RuleWorkLinks.Link>> reports = "review".equals(queue)
				? links.matchedReports(pageRules.stream()
						.map(rule -> new RuleWorkLinks.RuleRef(rule.id(), rule.name(), rule.revision())).toList(), since)
				: Map.of();
		return pageRules.stream().map(rule -> {
			var counts = judgments.getOrDefault(rule.id(), Map.of());
			long fp = counts.getOrDefault("FALSE_POSITIVE", 0L);
			long reviewed = fp + counts.getOrDefault("TRUE_POSITIVE", 0L);
			long unknown = counts.getOrDefault("UNKNOWN", 0L);
			return "review".equals(queue)
					? reviewItem(rule, matches.getOrDefault(rule.id(), 0L), reviewed, unknown, filter,
							reports.getOrDefault(rule.id(), List.of()))
					: investigateItem(rule, reviewed, fp, filter);
		}).toList();
	}

	private static boolean current(List<RuleRow> rules, Map<String, Object> row) {
		Object id = row.get("rule_id");
		return rules.stream().anyMatch(rule -> Objects.equals(rule.id(), id)
				&& Objects.equals(rule.revision(), row.get("revision")));
	}

	private WorkItem reviewItem(RuleRow rule, long matched, long reviewed, long unknown, Filter filter,
			List<RuleWorkLinks.Link> reports) {
		long minimum = health.minimumSample();
		boolean tooFew = matched > 0 && reviewed < minimum;
		String why = tooFew ? "Too few reviewed findings to judge this rule (" + reviewed + " of " + minimum + " needed)"
				: "Findings were marked Unknown and need a decision";
		String evidence = matched + " matches in " + filter.days() + " days · " + reviewed + " reviewed"
				+ (unknown > 0 ? " · " + unknown + " marked Unknown" : "");
		Meter meter = tooFew ? new Meter(reviewed, minimum, reviewed + " of " + minimum + " reviewed",
				"Too few reviewed findings to judge this rule: " + minimum + " reviews are needed.", false) : null;
		Chip state = tooFew ? null : new Chip("Marked Unknown", "help_outline", "warn", why);
		List<Chip> chips = new ArrayList<>();
		chips.add(new Chip(plural(matched, "match", "matches"), "bug_report", "",
				"Matches in the last " + filter.days() + " days"));
		chips.add(new Chip(reviewed + " reviewed", "done_all", "", "Marked true or false positive by a person"));
		if (unknown > 0) {
			chips.add(new Chip(unknown + " marked Unknown", "help_outline", "warn", "Someone could not decide yet"));
		}
		// The most recent report opens filtered to the rule, where Review finding is one click away.
		String url = reports.isEmpty() ? "/rules/" + rule.id() + "/health?days=" + filter.days() : reports.get(0).url();
		return item(rule, why, evidence, state, meter, chips, "Review findings", "rate_review", url, null);
	}

	private static WorkItem investigateItem(RuleRow rule, long reviewed, long falsePositives, Filter filter) {
		long percent = reviewed == 0 ? 0 : Math.round(100.0 * falsePositives / reviewed);
		String why = "Reviewed findings suggest this rule is noisy";
		String evidence = falsePositives + " of " + reviewed + " reviewed findings are false positives (" + percent
				+ "%) in " + filter.days() + " days";
		return item(rule, why, evidence, new Chip("Noisy", "campaign", "bad", why),
				new Meter(falsePositives, reviewed, falsePositives + " of " + reviewed + " false positives (" + percent + "%)",
						evidence, true),
				List.of(), "Investigate rule", "troubleshoot", "/rules/" + rule.id() + "/health?days=" + filter.days(),
				null);
	}

	private static WorkItem reviewsItem(RuleRow rule) {
		LocalDate due = rule.reviewBy();
		boolean overdue = due != null && due.isBefore(LocalDate.now(ZoneOffset.UTC));
		String why = overdue ? "Review overdue since " + due : "Open or in-progress rule review";
		String evidence = overdue ? "The review-by date " + due + " has passed" : "A saved review is waiting for an outcome";
		Chip state = overdue ? new Chip("Overdue", "schedule", "bad", why)
				: new Chip("In progress", "pending_actions", "info", evidence);
		List<Chip> chips = due == null ? List.of()
				: List.of(new Chip("Due " + due.format(DUE), "event", overdue ? "bad" : "",
						overdue ? evidence : "Review by " + due));
		return item(rule, why, evidence, state, null, chips, "Open reviews", "fact_check",
				"/rules/" + rule.id() + "/reviews?state=pending", null);
	}

	private static WorkItem candidateItem(RuleCandidateEntity candidate, RuleRow rule) {
		boolean draft = "DRAFT".equals(candidate.status);
		boolean stale = !Objects.equals(candidate.baseRevision, rule.revision());
		String why = draft ? "Draft candidate: test it against reviewed examples"
				: "In shadow: inspect shadow evidence, then promote or reject";
		String evidence = "Proposed by " + candidate.reviewer + " · " + candidate.rationale
				+ (stale ? " · the rule changed after this candidate was drafted" : "");
		Chip state = draft ? new Chip("Draft", "edit_note", "", why) : new Chip("In shadow", "visibility", "shadow", why);
		List<Chip> chips = new ArrayList<>();
		chips.add(new Chip(candidate.reviewer, "person", "", "Proposed by " + candidate.reviewer + ": " + candidate.rationale));
		if (stale) {
			chips.add(new Chip("Rule changed since", "history", "warn", "The rule changed after this candidate was drafted"));
		}
		return item(rule, why, evidence, state, null, chips, draft ? "Prepare examples and compare" : "Decide",
				draft ? "compare" : "gavel", "/rules/" + rule.id() + "/candidates", candidate.updatedAt);
	}

	private static WorkItem setupItem(RuleRow rule, Filter filter) {
		List<Chip> missing = new ArrayList<>();
		if (rule.owner() == null || rule.owner().isBlank()) {
			missing.add(new Chip("Owner", "person_off", "warn", "No owner or team is set"));
		}
		if (!rule.notSecurity() && (rule.cwe() == null || rule.cwe().isBlank())) {
			missing.add(new Chip("CWE", "label_off", "warn", "No CWE weakness ID is set"));
		}
		if (missing.isEmpty()) {
			// Only the scan-based gap can list a rule that has an owner and a CWE.
			String evidence = "No matches in " + filter.days() + " days although its engine ran";
			return item(rule, "Coverage gap, not a confirmed quality problem", evidence, null, null,
					List.of(new Chip("No recent matches", "search_off", "warn", evidence)), "Check coverage",
					"monitor_heart", "/rules/" + rule.id() + "/health?days=" + filter.days(), null);
		}
		String url = filter.canModify() ? "/rule/edit/" + rule.module() + "/" + rule.id() : null;
		return item(rule, "Setup gap, not a confirmed quality problem",
				String.join(" · ", missing.stream().map(chip -> "No " + (chip.text().equals("CWE") ? "CWE" : "owner")).toList()), null, null, missing,
				filter.canModify() ? "Set owner and CWE" : "Ask a rule maintainer to set owner and CWE", "edit", url,
				null);
	}

	private static WorkItem item(RuleRow rule, String why, String evidence, Chip state, Meter meter, List<Chip> chips,
			String action, String actionIcon, String url, Long updatedAt) {
		return new WorkItem(rule.id(), ScannerIdentity.withoutScannerPrefix(rule.name()),
				ScannerIdentity.of(rule.module()), rule.owner(), rule.reviewBy(), why,
				evidence, state, meter, chips, action, actionIcon, url, updatedAt);
	}

	private static String plural(long count, String one, String many) {
		return count + " " + (count == 1 ? one : many);
	}
}
