package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.util.List;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;

/**
 * Published once a pull request scan and all of its violations are persisted, so a module can
 * react to the result (e.g. alert on new secrets) without the scan depending on it.
 * <p>
 * It is published on the scan thread. A listener that does anything slow or fallible must run
 * asynchronously on its own executor; a listener exception is logged and never fails the scan.
 * Every save in {@code PRScanResultService.savePullRequestScan} commits on its own, so the rows
 * are committed by publish time. A listener that may someday run inside a surrounding
 * transaction should use {@code @TransactionalEventListener(fallbackExecution = true)}.
 *
 * @param scanId      id of the saved scan
 * @param pullRequest the scanned pull request
 * @param findings    a snapshot of the scan's violations, including the transient new/blocking
 *                    flags the scan computed
 * @author Watchtower
 */
public record PRScanCompletedEvent(long scanId, PullRequest pullRequest,
		List<Finding> findings) {

	public PRScanCompletedEvent {
		findings = List.copyOf(findings);
	}

	/**
	 * One violation as the scan saw it. Holds no source content.
	 *
	 * @param violationId  the saved violation's id
	 * @param ruleName     the rule (violation) name
	 * @param severity     the priority the violation was reported at
	 * @param fileName     the file path, relative to the repository root
	 * @param lineNum      the flagged line
	 * @param newViolation whether the flagged line is new in this pull request
	 * @param blocking     whether the violation blocks the pull request
	 */
	public record Finding(long violationId, String ruleName, RulePriority severity,
			String fileName, int lineNum, boolean newViolation, boolean blocking) {

		/**
		 * @param violation a saved violation
		 * @return its snapshot
		 */
		public static Finding of(PullRequestViolationEntity violation) {
			return new Finding(violation.getId(), violation.getViolationName(),
					violation.getSeverity(), violation.getFileName(), violation.getLineNum(),
					violation.isNewViolation(), violation.isBlocking());
		}
	}
}
