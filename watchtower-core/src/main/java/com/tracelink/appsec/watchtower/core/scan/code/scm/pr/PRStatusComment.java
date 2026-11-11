package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;

/**
 * One small comment on a pull request that says where its scan is: started, local checks done, the AWS review running, and the
 * result. It is created when the scan starts and edited as the scan moves, so a pull request carries one status comment, not one per
 * step. It never carries findings or any provider text: the findings are in the summary comment and the report this links to.
 *
 * <p>Posting is best effort. A failure to list, post or edit is logged and swallowed, because a status note must never affect a scan.
 */
public final class PRStatusComment {

	private static final Logger LOG = LoggerFactory.getLogger(PRStatusComment.class);

	/** The footer that marks the comment as Watchtower's status comment, so it is found again and edited, never duplicated. */
	static final String MARKER = "_Watchtower · scan status_";

	private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL");

	private PRStatusComment() {
	}

	/** How far the scan has got. */
	public enum Phase {
		/** The scan has started and its local checks are running. */
		STARTED,
		/** The local checks finished and a remote review (AWS) is still running. */
		LOCAL_DONE_REMOTE_RUNNING,
		/** Everything this scan involves has finished. */
		FINISHED
	}

	/** The outcome shown once a scan is {@link Phase#FINISHED}. */
	public enum Result {
		PASSED, BLOCKED,
		/** A remote review could not finish and the policy passed the pull request. */
		PASSED_BY_POLICY,
		/** A remote review could not finish and the pull request stays marked incomplete. */
		INCOMPLETE,
		/** A newer commit replaced the one this scan reviewed. */
		SUPERSEDED
	}

	/**
	 * What the comment says.
	 *
	 * @param commit          the scanned commit, or null
	 * @param phase           how far the scan has got
	 * @param remoteInvolved  whether an AWS review is part of this scan
	 * @param localFindings   findings from Watchtower's own scanners, or null while they run
	 * @param remoteFindings  findings the AWS review returned, or null when it has not finished
	 * @param remoteSeverity  those findings by severity name, for a short "2 High, 1 Low", or null
	 * @param result          the outcome once finished, or null
	 * @param reportLink      the Watchtower report, or null without a public URL
	 */
	public record Status(String commit, Phase phase, boolean remoteInvolved, Integer localFindings,
			Integer remoteFindings, Map<String, Integer> remoteSeverity, Result result, String reportLink,
			String summary) {
		public Status(String commit, Phase phase, boolean remoteInvolved, Integer localFindings,
				Integer remoteFindings, Map<String, Integer> remoteSeverity, Result result, String reportLink) {
			this(commit, phase, remoteInvolved, localFindings, remoteFindings, remoteSeverity, result, reportLink, null);
		}
	}

	/**
	 * One AWS finding as the comment shows it: a priority, a plain title and where it is. Never source code and never the provider's
	 * own prose.
	 *
	 * @param priority the severity name, e.g. High
	 * @param title    the plain title; a secret-like finding has a generic one
	 * @param file     the file, or null when the review gave no usable location
	 * @param line     the line in that file
	 * @param blocking whether it blocks the pull request
	 * @param bypassed whether an active bypass covers a blocking finding
	 */
	public record Row(String priority, String title, String file, int line, boolean blocking, boolean bypassed) {
	}

	/**
	 * What a remote review (the AWS review) returned, for the one line it takes in the final summary.
	 *
	 * @param findings the findings it returned, or null when it could not finish
	 * @param severity those findings by severity name, or null
	 * @param blocking how many of them block the pull request
	 */
	public record Remote(Integer findings, Map<String, Integer> severity, int blocking, List<Row> rows) {
		/** The AWS findings listed in the comment; the rest are counted and left to the report. */
		public static final int MAX_ROWS = 10;

		public Remote(Integer findings, Map<String, Integer> severity, int blocking) {
			this(findings, severity, blocking, List.of());
		}

		public Remote {
			rows = rows == null ? List.of() : List.copyOf(rows);
		}

		boolean noFindings() {
			return findings != null && findings == 0;
		}

		String line() {
			if (findings == null) {
				return PROBLEM + " **AWS Security Agent:** did not finish";
			}
			if (findings == 0) {
				return DONE + " **AWS Security Agent:** no findings";
			}
			String by = severities(severity);
			return "☁️ **AWS Security Agent:** " + count(findings) + (by.isEmpty() ? "" : " (" + by + ")")
					+ (blocking > 0 ? " · " + blocking + " blocking" : "");
		}
	}

	/**
	 * The scan summary a finished scan's one comment becomes: the same summary any scanner gets, with the remote review as one line.
	 * Findings must already leave out MCR findings.
	 */
	public static String finalSummary(List<com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity> findings,
			java.util.Collection<String> incompleteScanners, com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass appliedBypass,
			int notInline, String commit, String reportLink, boolean bypassRequestable, Remote remote) {
		return new PRScanSummary(findings, incompleteScanners, appliedBypass, notInline, commit, reportLink, bypassRequestable, remote)
				.toMarkdown();
	}

	/**
	 * Creates the pull request's status comment, or edits it when it is already there.
	 *
	 * @return true if the comment is now in step with {@code status}, or the integration is configured not to comment; false if it
	 *         could not be posted
	 */
	public static boolean post(IScmApi api, PullRequest pullRequest, Status status) {
		try {
			String text = toMarkdown(status);
			List<PullRequestComment> comments = api.listComments(pullRequest);
			if (comments == null) {
				// The comments could not be read; posting now could duplicate the status comment.
				LOG.warn("Not posting the status comment on {}: its comments could not be read", pullRequest.getPRString());
				return false;
			}
			PullRequestComment existing = comments.stream()
					.filter(c -> !c.isInline() && c.raw() != null && c.raw().strip().endsWith(MARKER)).findFirst().orElse(null);
			if (existing == null) {
				return api.sendComment(pullRequest, text);
			}
			if (Objects.equals(existing.raw().strip(), text.strip())) {
				return true;
			}
			return api.updateComment(pullRequest, existing.id(), text);
		} catch (RuntimeException e) {
			LOG.warn("Could not post the status comment on {}", pullRequest.getPRString(), e);
			return false;
		}
	}

	private static final String DONE = "✅";
	private static final String PROBLEM = "⚠️";

	/**
	 * The comment's markdown. While the scan runs it is one headline and one line saying where it is; when it has finished it is the
	 * scan summary any scanner gets (see {@link #finalSummary}), or a headline alone when there is none. Package-private for tests.
	 */
	static String toMarkdown(Status s) {
		List<String> lines = new java.util.ArrayList<>();
		if (s.phase() == Phase.FINISHED && StringUtils.isNotBlank(s.summary())) {
			lines.add(s.summary().strip());
		} else {
			lines.add("### 🛡️ Watchtower — " + headline(s));
			String detail = detail(s);
			if (detail != null) {
				lines.add("");
				lines.add(detail);
			}
			List<String> footer = new java.util.ArrayList<>();
			if (StringUtils.isNotBlank(s.commit())) {
				footer.add("commit `" + PRCommentFormat.shortCommit(s.commit()) + "`");
			}
			if (StringUtils.isNotBlank(s.reportLink())) {
				footer.add("[View scan](" + s.reportLink() + ")");
			}
			if (!footer.isEmpty()) {
				lines.add("");
				lines.add(String.join(" · ", footer));
			}
		}
		lines.add("");
		lines.add(MARKER);
		return String.join("\n", lines);
	}

	private static String headline(Status s) {
		return switch (s.phase()) {
			case STARTED -> "started scanning";
			case LOCAL_DONE_REMOTE_RUNNING -> "scan in progress";
			case FINISHED -> s.result() == null ? "scan finished" : switch (s.result()) {
				case PASSED -> DONE + " Scan passed";
				case BLOCKED -> PRCommentFormat.BLOCKING + " Blocking issues found";
				case PASSED_BY_POLICY -> PROBLEM + " AWS could not finish, passed by policy";
				case INCOMPLETE -> PROBLEM + " AWS could not finish, marked incomplete";
				case SUPERSEDED -> "A newer commit replaced this one";
			};
		};
	}

	/** The one line under the headline while the scan runs. */
	private static String detail(Status s) {
		if (s.phase() != Phase.LOCAL_DONE_REMOTE_RUNNING) {
			return null;
		}
		String local = s.localFindings() == null ? "Watchtower's scanners have finished"
				: "Watchtower's scanners have finished with " + count(s.localFindings());
		return local + ". The AWS Security Agent review is still running; this comment is updated when it ends.";
	}

	private static String count(int findings) {
		return findings == 1 ? "1 finding" : findings + " findings";
	}

	/** "2 High, 1 Low", worst first; names it does not know follow. */
	private static String severities(Map<String, Integer> counts) {
		if (counts == null || counts.isEmpty()) {
			return "";
		}
		return counts.entrySet().stream().filter(e -> e.getKey() != null && !e.getKey().isBlank() && e.getValue() != null && e.getValue() > 0)
				.sorted(java.util.Comparator.comparingInt((Map.Entry<String, Integer> e) -> {
					int rank = SEVERITY_ORDER.indexOf(e.getKey().toUpperCase(java.util.Locale.ROOT));
					return rank < 0 ? SEVERITY_ORDER.size() : rank;
				}).thenComparing(Map.Entry::getKey))
				.map(e -> e.getValue() + " " + e.getKey().substring(0, 1).toUpperCase(java.util.Locale.ROOT)
						+ e.getKey().substring(1).toLowerCase(java.util.Locale.ROOT))
				.collect(java.util.stream.Collectors.joining(", "));
	}

	/**
	 * The pull request's latest Watchtower report, found by repository and pull request so it stays valid across scans.
	 *
	 * @return the link, or null without a public URL
	 */
	public static String reportLink(String publicUrl, PullRequest pullRequest) {
		if (StringUtils.isBlank(publicUrl)) {
			return null;
		}
		return StringUtils.removeEnd(publicUrl.trim(), "/") + "/scan/report/latest?apiLabel="
				+ encode(pullRequest.getApiLabel()) + "&repo=" + encode(pullRequest.getRepoName()) + "&prId="
				+ encode(pullRequest.getPrId());
	}

	private static String encode(String value) {
		return URLEncoder.encode(StringUtils.defaultString(value), StandardCharsets.UTF_8);
	}
}
