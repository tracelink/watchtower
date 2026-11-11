package com.tracelink.appsec.watchtower.core.scan.code.scm.repo;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

/**
 * A background job on the repository scan Queue tab, in plain words (UAT walkthrough,
 * 2026-10-16): an icon tile, a result chip that tells the truth (an integration check that found
 * a failing integration is amber "1 of 2 failing", not a green "Completed"), and the job's
 * counts as chips ("1 repository", "0 changed", "0 gone").
 *
 * @param title      the job's name
 * @param icon       the job's icon
 * @param result     the result chip's text
 * @param tone       the result chip's tone (success, warning, danger, info, neutral)
 * @param resultIcon the result chip's icon
 * @param resultTip  the result's meaning, shown on hover
 * @param link       where a click on the result goes, or null
 * @param chips      the job's counts
 * @param createdAt  when the job was queued
 */
public record QueueJobView(String title, String icon, String result, String tone,
		String resultIcon, String resultTip, String link, List<String> chips, long createdAt, long id,
		boolean diagnosable) {

	/** A view without the job id; the id and the diagnose flag are filled in by {@link #of(AsyncJobEntity)}. */
	public QueueJobView(String title, String icon, String result, String tone, String resultIcon,
			String resultTip, String link, List<String> chips, long createdAt) {
		this(title, icon, result, tone, resultIcon, resultTip, link, chips, createdAt, 0, false);
	}

	static final String INTEGRATIONS = "/apisettings";

	/** "2 checked, 1 failing" or "2 checked, 1 failing: Example (Amazon ECR)". */
	private static final Pattern CHECK = Pattern.compile("^(\\d+) checked, (\\d+) failing(?:: (.+))?$");

	/** "1 repositories, 0 changed, 0 gone" (the sync's final note). */
	private static final Pattern SYNC = Pattern.compile("^(\\d+) repositories, (\\d+) changed, (\\d+) gone$");

	/** The recent-jobs filter on the Queue tab. */
	public enum Filter {
		ALL("all", "All", "list", List.of()),
		CHECKS("checks", "Integration checks", "verified", List.of(AsyncJobType.INTEGRATION_HEALTH)),
		SYNCS("syncs", "Repository syncs", "sync", List.of(AsyncJobType.CATALOG_SYNC)),
		RUNS("runs", "Scan runs", "playlist_add", List.of(AsyncJobType.EXPAND_PLAN, AsyncJobType.EXPORT_RUN));

		private final String key;
		private final String label;
		private final String icon;
		private final List<AsyncJobType> types;

		Filter(String key, String label, String icon, List<AsyncJobType> types) {
			this.key = key;
			this.label = label;
			this.icon = icon;
			this.types = types;
		}

		public String key() {
			return key;
		}

		public String label() {
			return label;
		}

		public String icon() {
			return icon;
		}

		/** The job types this filter shows; empty for All. */
		public List<AsyncJobType> types() {
			return types;
		}

		public static Filter of(String key) {
			for (Filter filter : values()) {
				if (filter.key.equals(key)) {
					return filter;
				}
			}
			return ALL;
		}
	}

	/** Job types shown on the Queue page whose failures the assistant can explain. */
	private static final java.util.Set<AsyncJobType> DIAGNOSABLE = java.util.Set.of(AsyncJobType.CATALOG_SYNC,
			AsyncJobType.EXPAND_PLAN, AsyncJobType.EXPORT_RUN, AsyncJobType.INTEGRATION_HEALTH);

	public static QueueJobView of(AsyncJobEntity job) {
		QueueJobView view = describe(job);
		boolean failing = "danger".equals(view.tone()) || "warning".equals(view.tone());
		return new QueueJobView(view.title(), view.icon(), view.result(), view.tone(), view.resultIcon(),
				view.resultTip(), view.link(), view.chips(), view.createdAt(), job.getId(),
				failing && DIAGNOSABLE.contains(job.getType()));
	}

	private static QueueJobView describe(AsyncJobEntity job) {
		AsyncJobType type = job.getType();
		String title = type == null ? "Job" : type.getDisplayName();
		String icon = iconOf(type);
		String progress = job.getProgress() == null ? "" : job.getProgress().trim();
		long createdAt = job.getCreatedAt();
		AsyncJobStatus status = job.getStatus();
		if (status == AsyncJobStatus.FAILED) {
			String error = job.getError() == null || job.getError().isBlank() ? "The job failed." : job.getError();
			return new QueueJobView(title, icon, "Failed", "danger", "error", error, null,
					chipsOf(progress), createdAt);
		}
		if (status != AsyncJobStatus.DONE) {
			boolean running = status == AsyncJobStatus.RUNNING;
			return new QueueJobView(title, icon, running ? "Running" : "Queued", running ? "info" : "neutral",
					running ? "sync" : "schedule", running ? "In progress." : "Waiting to start.", null,
					chipsOf(progress), createdAt);
		}
		if (type == AsyncJobType.INTEGRATION_HEALTH) {
			Matcher check = CHECK.matcher(progress);
			if (check.matches()) {
				return ofCheck(title, icon, check, createdAt);
			}
		}
		if (type == AsyncJobType.CATALOG_SYNC) {
			Matcher sync = SYNC.matcher(progress);
			if (sync.matches()) {
				int listed = Integer.parseInt(sync.group(1));
				return done(title, icon, List.of(listed + (listed == 1 ? " repository" : " repositories"),
						sync.group(2) + " changed", sync.group(3) + " gone"), createdAt);
			}
		}
		return done(title, icon, chipsOf(progress), createdAt);
	}

	private static QueueJobView ofCheck(String title, String icon, Matcher check, long createdAt) {
		int checked = Integer.parseInt(check.group(1));
		int failing = Integer.parseInt(check.group(2));
		List<String> chips = List.of(checked + " checked");
		if (failing == 0) {
			return new QueueJobView(title, icon, "Done", "success", "check_circle",
					"All " + checked + (checked == 1 ? " integration" : " integrations") + " connected.", null,
					chips, createdAt);
		}
		String names = check.group(3);
		String tip = names == null || names.isBlank()
				? failing + (failing == 1 ? " integration" : " integrations") + " failed its check."
				: names + (failing == 1 ? " failed its check." : " failed their checks.");
		return new QueueJobView(title, icon, failing + " of " + checked + " failing", "warning", "warning",
				tip + " Click to open Integrations.", INTEGRATIONS, chips, createdAt);
	}

	private static QueueJobView done(String title, String icon, List<String> chips, long createdAt) {
		return new QueueJobView(title, icon, "Done", "success", "check_circle", "Finished without errors.", null,
				chips, createdAt);
	}

	private static List<String> chipsOf(String progress) {
		return progress.isEmpty() ? List.of() : List.of(progress);
	}

	private static String iconOf(AsyncJobType type) {
		if (type == null) {
			return "work";
		}
		return switch (type) {
			case INTEGRATION_HEALTH -> "verified";
			case CATALOG_SYNC -> "sync";
			case EXPAND_PLAN -> "playlist_add";
			case EXPORT_RUN -> "download";
			case RULE_CANDIDATE_TEST -> "science";
			case VARIANT_SEARCH -> "travel_explore";
			case UPSTREAM_CHECK -> "update";
			case ASSISTANT_EVALUATION -> "auto_awesome";
			case AI_BATCH_TRIAGE -> "fact_check";
			case CWE_CATALOG_REFRESH -> "menu_book";
			case AI_CODE_REVIEW -> "manage_search";
			case WEBHOOK_SYNC, WEBHOOK_BULK -> "webhook";
		};
	}
}
