package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertItem;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * The scan-health alerts and metrics of one pull request scan: a sensitive scanner that did not
 * finish, and SCM calls (comment, decline, approve, request changes) that failed. Both are
 * optional - without an {@link AlertService} or {@link MeterRegistry} nothing is raised or counted.
 * Deduped per commit, so an SQS redelivery of the same commit does not alert twice.
 *
 * @author Watchtower
 */
class PRScanAlerts {

	static final String INCOMPLETE_METRIC = "watchtower.scan.incomplete";

	static final String SCM_ACTION_METRIC = "watchtower.scm.review.actions";

	/** An SCM call made while reporting a scan. */
	enum ScmAction {
		COMMENT("Posting the scan report comment"),
		DECLINE("Declining"),
		APPROVE("Approving"),
		REQUEST_CHANGES("Requesting changes");

		private final String description;

		ScmAction(String description) {
			this.description = description;
		}
	}

	private final AlertService alertService;

	private final MeterRegistry meterRegistry;

	private final List<ScmAction> failedActions = new ArrayList<>();

	PRScanAlerts(AlertService alertService, MeterRegistry meterRegistry) {
		this.alertService = alertService;
		this.meterRegistry = meterRegistry;
	}

	/**
	 * @param pr       the scanned pull request
	 * @param scanners display names of the sensitive scanners that did not finish
	 */
	void scanIncomplete(PullRequest pr, Collection<String> scanners) {
		if (scanners.isEmpty()) {
			return;
		}
		if (meterRegistry != null) {
			scanners.forEach(scanner -> meterRegistry
					.counter(INCOMPLETE_METRIC, "scanner", scanner).increment());
		}
		// Only the scanner name: its error text stays in the logs, in case it echoes content.
		raise(pr, AlertTypeRegistry.SCANNER_FAILURE,
				"Scan incomplete for pull request #" + pr.getPrId(),
				scanners.stream().map(scanner -> new AlertItem(dedupeKey(pr, "scanner:" + scanner),
						null, scanner + " did not finish, so findings may be missing. Details"
								+ " are in the Watchtower logs."))
						.toList());
	}

	/**
	 * @param action    the call made
	 * @param succeeded its outcome, as the SCM API reported it
	 */
	void recordScmAction(ScmAction action, boolean succeeded) {
		if (meterRegistry != null) {
			meterRegistry.counter(SCM_ACTION_METRIC, "action",
					action.name().toLowerCase(Locale.ROOT), "outcome", succeeded ? "ok" : "failed")
					.increment();
		}
		if (!succeeded) {
			failedActions.add(action);
		}
	}

	/**
	 * @param pr the scanned pull request
	 */
	void raiseFailedScmActions(PullRequest pr) {
		if (failedActions.isEmpty()) {
			return;
		}
		raise(pr, AlertTypeRegistry.SCM_REVIEW_ACTION_FAILED,
				"Watchtower could not update pull request #" + pr.getPrId(),
				failedActions.stream().map(action -> new AlertItem(
						dedupeKey(pr, "scm:" + action.name()), null,
						action.description + " failed")).toList());
	}

	private void raise(PullRequest pr, String type, String title, List<AlertItem> items) {
		if (alertService == null) {
			return;
		}
		alertService.raise(new AlertEvent(type, pr.getApiLabel(), pr.getRepoName(), title, null,
				String.join("\u0000", "scan-health", pr.getApiLabel(), pr.getRepoName(),
						pr.getPrId()),
				items));
	}

	private static String dedupeKey(PullRequest pr, String what) {
		return String.join("\u0000", pr.getApiLabel(), pr.getRepoName(), pr.getPrId(),
				pr.getCommitHash(), what);
	}
}
