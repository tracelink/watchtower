package com.tracelink.appsec.module.betterleaks.alerting;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleDto;
import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertItem;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanCompletedEvent;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanCompletedEvent.Finding;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.scan.RepoScanCompletedEvent;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

import jakarta.annotation.PreDestroy;

/**
 * Raises a {@link #SECRET_DETECTED} alert when a pull request scan finds secrets on new lines.
 * The alert is handed to {@link AlertService} on this listener's own thread, so a slow database
 * or a full queue can never delay or fail the scan. Alerts carry the rule, file and line - never
 * the secret, which Betterleaks redacts before it reaches Watchtower.
 *
 * @author Watchtower
 */
@Component
public class BetterleaksAlertListener {

	private static final Logger LOG = LoggerFactory.getLogger(BetterleaksAlertListener.class);

	/** Betterleaks found a secret on a new line of a pull request. */
	public static final String SECRET_DETECTED = "SECRET_DETECTED";

	/** Bounds memory if the database is down while scans keep finishing. */
	private static final int QUEUE_CAPACITY = 1000;

	private static final String SEPARATOR = " · ";

	private final AlertService alertService;

	private final String publicUrl;

	private final Executor executor;

	@Autowired
	public BetterleaksAlertListener(AlertService alertService, AlertTypeRegistry registry,
			@Value("${watchtower.publicUrl:#{null}}") String publicUrl) {
		this(alertService, registry, publicUrl, newExecutor());
	}

	BetterleaksAlertListener(AlertService alertService, AlertTypeRegistry registry,
			String publicUrl, Executor executor) {
		this.alertService = alertService;
		this.publicUrl = publicUrl;
		this.executor = executor;
		registry.register(SECRET_DETECTED, "Betterleaks found a secret on a new line of a pull"
				+ " request.", true);
	}

	/**
	 * @param pr a pull request
	 * @return the chat thread its secrets alerts share
	 */
	public static String threadKey(PullRequest pr) {
		return String.join("\u0000", "secrets", pr.getApiLabel(), pr.getRepoName(), pr.getPrId());
	}

	/**
	 * @param publicUrl Watchtower's external base url ({@code watchtower.publicUrl}), may be blank
	 * @param scanId    a pull request scan
	 * @return the scan report's url, or null if no public url is configured
	 */
	public static String reportLink(String publicUrl, long scanId) {
		return StringUtils.isBlank(publicUrl) ? null
				: StringUtils.removeEnd(publicUrl.trim(), "/") + "/scan/report/" + scanId;
	}

	/**
	 * @param event a saved pull request scan
	 */
	@EventListener
	public void onScanCompleted(PRScanCompletedEvent event) {
		List<Finding> secrets = event.findings().stream()
				.filter(Finding::newViolation)
				.filter(f -> StringUtils.startsWith(f.ruleName(), BetterleaksRuleDto.NAME_PREFIX))
				.toList();
		if (secrets.isEmpty()) {
			return;
		}
		// Built here, so the task holds an immutable snapshot rather than the mutable PullRequest.
		AlertEvent alert = toAlert(event, secrets);
		try {
			executor.execute(() -> alertService.raise(alert));
		} catch (RejectedExecutionException e) {
			LOG.warn("Dropped the secrets alert for scan {}: the alert queue is full",
					event.scanId());
		}
	}

	/**
	 * Alerts on secrets a repository scan found that the previous scan of the branch did not
	 * have. A branch's first scan is a baseline with no new findings, so it raises nothing.
	 *
	 * @param event a stored repository scan
	 */
	@EventListener
	public void onRepoScanCompleted(RepoScanCompletedEvent event) {
		List<RepoScanReport.Finding> secrets = event.newFindings().stream()
				.filter(f -> StringUtils.startsWith(f.rule(), BetterleaksRuleDto.NAME_PREFIX))
				.toList();
		if (secrets.isEmpty()) {
			return;
		}
		String link = StringUtils.isBlank(publicUrl) ? null
				: StringUtils.removeEnd(publicUrl.trim(), "/") + "/reposcan/report/"
						+ event.scanId();
		List<AlertItem> items = secrets.stream().map(f -> {
			String rule = StringUtils.removeStart(f.rule(), BetterleaksRuleDto.NAME_PREFIX);
			String dedupeKey = String.join("\u0000", event.apiLabel(), event.repository(),
					event.branch(), f.fingerprint());
			RulePriority severity = RulePriority.priorityForName(f.severity());
			String text = String.join(SEPARATOR, f.severity(), rule, f.file() + ":" + f.line());
			return new AlertItem(dedupeKey, severity, text);
		}).toList();
		AlertEvent alert = new AlertEvent(SECRET_DETECTED, event.apiLabel(), event.repository(),
				"New secrets in " + event.repository() + " (" + event.branch() + ")", link,
				String.join("\u0000", "secrets", event.apiLabel(), event.repository(),
						event.branch()),
				items);
		try {
			executor.execute(() -> alertService.raise(alert));
		} catch (RejectedExecutionException e) {
			LOG.warn("Dropped the secrets alert for repository scan {}: the alert queue is full",
					event.scanId());
		}
	}

	private AlertEvent toAlert(PRScanCompletedEvent event, List<Finding> secrets) {
		PullRequest pr = event.pullRequest();
		String title = "New secrets in pull request #" + pr.getPrId()
				+ (pr.getAuthor() == null ? "" : " by " + pr.getAuthor());
		String link = reportLink(publicUrl, event.scanId());
		List<AlertItem> items = secrets.stream().map(f -> toItem(pr, f)).toList();
		return new AlertEvent(SECRET_DETECTED, pr.getApiLabel(), pr.getRepoName(), title, link,
				threadKey(pr), items);
	}

	private static AlertItem toItem(PullRequest pr, Finding finding) {
		String rule = StringUtils.removeStart(finding.ruleName(), BetterleaksRuleDto.NAME_PREFIX);
		// Not the violation id or priority: a rescan of the same line must not alert again.
		String dedupeKey = String.join("\u0000", pr.getApiLabel(), pr.getRepoName(),
				pr.getPrId(), rule, finding.fileName(), String.valueOf(finding.lineNum()));
		String text = String.join(SEPARATOR,
				finding.severity() == null ? "Unknown" : finding.severity().getName(), rule,
				finding.fileName() + ":" + finding.lineNum(),
				finding.blocking() ? "blocking" : "not blocking");
		return new AlertItem(dedupeKey, finding.severity(), text);
	}

	private static ExecutorService newExecutor() {
		return new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
				new LinkedBlockingQueue<>(QUEUE_CAPACITY), runnable -> {
					Thread thread = new Thread(runnable, "betterleaks-alerts");
					thread.setDaemon(true);
					return thread;
				});
	}

	@PreDestroy
	void shutdown() {
		if (executor instanceof ExecutorService service) {
			service.shutdown();
		}
	}
}
