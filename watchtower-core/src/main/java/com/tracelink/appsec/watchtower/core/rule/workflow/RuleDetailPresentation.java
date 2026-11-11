package com.tracelink.appsec.watchtower.core.rule.workflow;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;
import com.tracelink.appsec.watchtower.core.rule.workflow.RuleWorkService.Chip;

/**
 * Plain-word pictures for the rule health and saved review pages (UAT walkthrough, 2026-10-16):
 * the calculated health map becomes tiles, a judgment bar and chips, and stored codes (OPEN,
 * IN_REVIEW, pull_request, nonblocking) become words. The calculations themselves are unchanged;
 * in particular the three zero-match states (#16) stay distinct.
 */
public final class RuleDetailPresentation {

	/** One choice in a filter or segmented control: the stored value, its words and icon. */
	public record Choice(String value, String label, String icon) {
	}

	/** A counted tile: icon, value, label and the meaning on hover. */
	public record Tile(String icon, String value, String label, String tip) {
	}

	/** True / false / unknown human judgments as a bar; percents add up to 100 when any exist. */
	public record Judgments(long truePositives, long falsePositives, long unknown) {
		public long total() {
			return truePositives + falsePositives + unknown;
		}

		public long truePercent() {
			return percent(truePositives);
		}

		public long falsePercent() {
			return percent(falsePositives);
		}

		public long unknownPercent() {
			return total() == 0 ? 0 : 100 - truePercent() - falsePercent();
		}

		public String tip() {
			return truePositives + " true positive" + plural(truePositives) + ", " + falsePositives + " false positive"
					+ plural(falsePositives) + ", " + unknown + " unknown";
		}

		private long percent(long part) {
			return total() == 0 ? 0 : Math.round(100.0 * part / total());
		}
	}

	/** Everything the health page draws from one calculated health map. */
	public record HealthView(List<Chip> headerChips, Chip evidenceChip, List<Tile> tiles, Judgments judgments,
			List<Chip> runChips) {
	}

	public static final List<Choice> REVIEW_STATUSES = List.of(
			new Choice("OPEN", "Open", "radio_button_unchecked"),
			new Choice("IN_REVIEW", "In review", "pending"),
			new Choice("ACCEPTED", "Accepted", "check_circle"),
			new Choice("REJECTED", "Rejected", "cancel"),
			new Choice("CLOSED", "Closed", "archive"));

	public static final List<Choice> SCAN_SCOPES = List.of(
			new Choice("all", "All scans", "radar"),
			new Choice("pull_request", "Pull requests", "merge"),
			new Choice("upload", "Uploads", "upload"),
			new Choice("repository", "Repositories", "code"));

	public static final List<Choice> POLICIES = List.of(
			new Choice("all", "All findings", "policy"),
			new Choice("blocking", "Blocking", "block"),
			new Choice("nonblocking", "Not blocking", "check"),
			new Choice("unknown", "Policy unknown", "help"));

	public static final List<Integer> WINDOWS = List.of(7, 30, 90);

	private static final String HOW_TO_READ = "Rates describe reviewed findings, which may be a selective sample, "
			+ "not overall precision. Informational findings are included. Reused scans are left out of run counts "
			+ "and review samples. Accepted risk and test code do not count as false positives. A rule being "
			+ "selected, an engine finishing and the rule actually being checked are different facts; a missing run "
			+ "record has an unknown cause unless a known exclusion is recorded.";

	private RuleDetailPresentation() {
	}

	/** The words for a stored review status; unknown codes are shown as given. */
	public static Choice reviewStatus(String code) {
		return find(REVIEW_STATUSES, code);
	}

	public static Choice scanScope(String code) {
		return find(SCAN_SCOPES, code);
	}

	public static Choice policy(String code) {
		return find(POLICIES, code);
	}

	/** The meaning of a "How to read this" chip on the health page. */
	public static String howToRead() {
		return HOW_TO_READ;
	}

	/** "2e7e2c2b" for a 64-character revision; "unknown" when none is recorded. */
	public static String shortRevision(String revision) {
		return revision == null ? "unknown" : revision.substring(0, Math.min(8, revision.length()));
	}

	/**
	 * The scope chip on Saved reviews, e.g. "Current revision · 90 d", with the full scope on hover.
	 */
	public static Chip scopeChip(String revision, String currentRevision, int days, String scanType,
			String policy) {
		boolean current = revision != null && revision.equals(currentRevision);
		String text = (revision == null ? "Unknown revision" : current ? "Current revision" : "Older revision")
				+ " · " + days + " d";
		String tip = "Revision " + (revision == null ? "not recorded" : revision) + ", last " + days + " days, "
				+ scanScope(scanType).label().toLowerCase(Locale.ROOT) + ", "
				+ policy(policy).label().toLowerCase(Locale.ROOT) + ". Carried over from Rule health.";
		return new Chip(text, "commit", current ? "" : "warn", tip);
	}

	/** Builds the health page's pictures from {@link RuleHealthService#health} output. */
	public static HealthView health(Map<String, Object> health, int minimumSample) {
		long sample = n(health, "reviewed_sample");
		return new HealthView(headerChips(health, sample, minimumSample), evidenceChip(health),
				tiles(health, sample), new Judgments(n(health, "tp"), n(health, "fp"), n(health, "unknown")),
				runChips(health));
	}

	/**
	 * The short health chips beside a rule's name on Rule editing and Suggest an improvement
	 * (Dev walk boards, 2026-10-22): "Too little data" with the count still needed on hover.
	 */
	public static List<Chip> compactHealthChips(Map<String, Object> health, int minimumSample) {
		long sample = n(health, "reviewed_sample");
		return headerChips(health, sample, minimumSample).stream()
				.map(chip -> "hourglass_empty".equals(chip.icon())
						? new Chip(TOO_LITTLE_DATA, chip.icon(), chip.tone(), sample < minimumSample
								? sample + " of " + minimumSample + " reviewed findings needed to judge this rule in "
										+ n(health, "days") + " days."
								: chip.tip())
						: chip)
				.toList();
	}

	/** The compact name of the insufficient-data health chip. */
	public static final String TOO_LITTLE_DATA = "Too little data";

	private static List<Chip> headerChips(Map<String, Object> health, long sample, int minimumSample) {
		List<Chip> chips = new ArrayList<>();
		Object raw = health.get("chips");
		if (!(raw instanceof List<?> names)) {
			return chips;
		}
		for (Object name : names) {
			chips.add(headerChip(String.valueOf(name), health, sample, minimumSample));
		}
		return chips;
	}

	private static Chip headerChip(String name, Map<String, Object> health, long sample, int minimumSample) {
		switch (name) {
			case RuleHealthService.INSUFFICIENT_DATA:
				return new Chip("Too little data to judge", "hourglass_empty", "warn", sample < minimumSample
						? "Too few findings have been reviewed by a person (" + sample + " of " + minimumSample
								+ " needed) to say whether the rule is accurate."
						: "Some scans in this scope have no run record, so whether the rule ran can't be confirmed.");
			case RuleHealthService.NO_RECENT_MATCHES:
				return new Chip("No recent matches", "search_off", "", "The engine ran but this rule matched nothing "
						+ "in this scope. That can mean the risk is absent from the scanned code; it is not a "
						+ "reason to retire the rule.");
			case RuleHealthService.NEEDS_REVIEW:
				return new Chip("Noisy", "campaign", "bad", n(health, "fp") + " of " + sample
						+ " reviewed findings were false positives. Look at the reviewed examples and start a review.");
			case "Review due":
				return new Chip("Review due", "event_busy", "bad", "The rule's review-by date has passed.");
			default:
				return new Chip(name, "info", "", name);
		}
	}

	/** One chip per #16 state; the stored explanation is its hover text. */
	private static Chip evidenceChip(Map<String, Object> health) {
		String note = String.valueOf(health.getOrDefault("evidence_note", ""));
		return switch (String.valueOf(health.get("evidence_state"))) {
			case "NO_ELIGIBLE_EVIDENCE" -> new Chip("No run records", "help", "warn", note);
			case "SUCCESSFUL_ENGINE_ZERO_MATCHES" -> new Chip("Ran, no matches", "task_alt", "ok", note);
			case "UNVERIFIED_ZERO_MATCHES" -> new Chip("No matches, run not confirmed", "help", "warn", note);
			default -> new Chip("Matches recorded", "bug_report", "", note);
		};
	}

	private static List<Tile> tiles(Map<String, Object> health, long sample) {
		long findings = n(health, "findings");
		Object rate = health.get("reviewed_fp_rate");
		Object coverage = health.get("review_coverage");
		return List.of(
				new Tile("bug_report", String.valueOf(findings), findings == 1 ? "Finding" : "Findings",
						"Findings this rule recorded in the chosen scope."),
				new Tile("done_all", String.valueOf(sample), "Reviewed by a person",
						"Findings with a true or false judgment."),
				new Tile("thumb_down", rate instanceof Number r ? percent(r.doubleValue()) : "—", "False positives",
						rate instanceof Number ? "Share of reviewed findings judged false. The reviewed sample may be "
								+ "selective." : "No reviewed findings with a judgment in this scope."),
				new Tile("percent", coverage instanceof Number c ? percent(c.doubleValue()) : "—", "Of findings reviewed",
						coverage instanceof Number ? "Reviewed findings out of all recorded findings."
								: "Unknown or not applicable: no findings, or more reviews than recorded findings."));
	}

	private static List<Chip> runChips(Map<String, Object> health) {
		long eligible = n(health, "selected_scans");
		long ran = n(health, "successful_engine_scans");
		long failed = n(health, "failed_scans");
		long skipped = n(health, "skipped_scans");
		long unknown = n(health, "unknown_scans");
		Object opportunities = health.get("known_opportunities");
		List<Chip> chips = new ArrayList<>();
		chips.add(new Chip(eligible + " eligible scan" + plural(eligible), "fact_check", "",
				"Scans that count towards this rule's numbers."));
		chips.add(new Chip(ran + " confirmed run" + plural(ran), ran == 0 ? "play_disabled" : "play_circle",
				ran == 0 ? "warn" : "ok",
				"Successful engine runs that recorded this rule. A rule being selected is not proof it ran."));
		chips.add(new Chip(failed + " failed", "error", failed > 0 ? "bad" : "", "Scans where the engine failed."));
		chips.add(new Chip(skipped + " skipped", "block", "",
				"Scans where the engine was skipped, unsupported or turned off."));
		chips.add(new Chip(unknown + " unknown", "help", unknown > 0 ? "warn" : "", "No run record exists for these "
				+ "scans. The cause is unknown; it does not mean the scan was clean or that data was lost."));
		chips.add(new Chip(opportunities instanceof Number o ? o + " checked places" : "Checked places: unknown",
				"functions", "", "How many places the rule actually checked"
						+ (opportunities instanceof Number ? "." : " is not recorded for this scope.")));
		chips.add(new Chip(n(health, "excluded_reviews") + " reviews left out", "filter_alt_off", "",
				"Reviews of findings from scans outside this scope's run records."));
		chips.add(new Chip(n(health, "bypass_events") + " PR bypasses", "lock_open", "",
				"Pull request bypasses that included this rule, counted separately from reviews."));
		return chips;
	}

	private static Choice find(List<Choice> choices, String code) {
		return choices.stream().filter(c -> c.value().equals(code)).findFirst()
				.orElse(new Choice(code, code == null ? "" : code, "label"));
	}

	private static String percent(double fraction) {
		return String.format(Locale.ROOT, "%.1f %%", fraction * 100);
	}

	private static String plural(long count) {
		return count == 1 ? "" : "s";
	}

	private static long n(Map<String, Object> values, String key) {
		return values.get(key) instanceof Number number ? number.longValue() : 0;
	}
}
