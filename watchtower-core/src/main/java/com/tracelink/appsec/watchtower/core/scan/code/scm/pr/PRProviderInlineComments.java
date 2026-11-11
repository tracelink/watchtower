package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;

/**
 * Puts a remote review's findings (the AWS review) on the changed lines of a pull request, the way local findings are: one comment on
 * the line of each finding, edited when it is already there, and noted as no longer reported when the latest review does not return
 * it. Only a finding's severity, plain title and a link to the report are posted. Never source code, never the provider's own prose,
 * and a finding that looks like a secret gets a generic title.
 *
 * <p>The provider does not tell us whether a finding of one review is the same finding in the next, so a comment that is not
 * returned again is not called fixed: it says it is no longer reported by the latest review, and stays as history. Only comments
 * carrying this footer marker are ever edited.
 */
public final class PRProviderInlineComments {

	private static final Logger LOG = LoggerFactory.getLogger(PRProviderInlineComments.class);

	/** New comments posted per review; the rest are counted for the caller. */
	public static final int MAX_INLINE = PRInlineComments.MAX_INLINE;

	private static final int REF_HASH_CHARS = 12;

	private static final Pattern MARKER = Pattern
			.compile("_Watchtower · aws ref ([0-9a-f]{" + REF_HASH_CHARS + "})-(\\d+)( · not reported)?_\\s*\\z");

	private static final Pattern TITLE = Pattern.compile("\\*\\*(.+?)\\*\\*");

	private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL");

	private PRProviderInlineComments() {
	}

	/**
	 * One finding on a changed line.
	 *
	 * @param path     the repository-relative file
	 * @param line     the line in the new version of the file, which must be part of the diff
	 * @param severity the provider's severity name, e.g. HIGH
	 * @param title    the plain title to show
	 * @param blocking whether this finding is at or above the blocking level
	 * @param bypassed whether an active bypass covers a blocking finding
	 */
	public record Finding(String path, int line, String severity, String title, boolean blocking, boolean bypassed) {
	}

	/**
	 * Comments the local scanners' findings on their lines for a pull request whose scan is waiting on a remote scanner. The scan
	 * stops at "local scanners done" then, so without this a finding found by a local scanner is never commented on its line.
	 *
	 * @param reported the scan's findings without MCR findings
	 * @param bypass   the bypass that stopped findings blocking, or null
	 * @return how many new findings have no inline comment (over the cap, or the post failed)
	 */
	public static int syncLocalFindings(IScmApi api, PullRequest pullRequest,
			List<com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity> reported,
			com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass bypass, String commit) {
		return new PRInlineComments(api, pullRequest).sync(reported, bypass, commit);
	}

	/**
	 * Brings the pull request's AWS finding comments in step with the latest review.
	 *
	 * @param link the Watchtower report to link, or null without a public URL
	 * @return how many findings could not be commented because of the per-review limit
	 */
	public static int sync(IScmApi api, PullRequest pullRequest, List<Finding> findings, String commit, String link) {
		List<PullRequestComment> comments = api.listComments(pullRequest);
		if (comments == null) {
			// Without the existing comments a post could duplicate one, so nothing is posted.
			LOG.warn("Not commenting AWS findings on {}: its comments could not be read", pullRequest.getPRString());
			return 0;
		}
		Map<String, PullRequestComment> active = ownActive(comments);
		Map<String, Finding> wanted = new LinkedHashMap<>();
		findings.stream().sorted(ORDER).forEach(f -> wanted.putIfAbsent(ref(f), f));
		int overLimit = 0;
		int index = 0;
		for (Map.Entry<String, Finding> entry : wanted.entrySet()) {
			if (index++ >= MAX_INLINE) {
				overLimit++;
				continue;
			}
			Finding f = entry.getValue();
			String text = text(f, entry.getKey(), link);
			PullRequestComment existing = active.remove(entry.getKey());
			if (existing == null) {
				api.sendInlineComment(pullRequest, f.path(), f.line(), text);
			} else if (!text.strip().equals(existing.raw().strip())) {
				api.updateComment(pullRequest, existing.id(), text);
			}
		}
		// What the latest review no longer returns stays as history, said plainly.
		for (Map.Entry<String, PullRequestComment> gone : active.entrySet()) {
			api.updateComment(pullRequest, gone.getValue().id(), notReported(gone.getValue().raw(), gone.getKey(), commit));
		}
		return overLimit;
	}

	private static final Comparator<Finding> ORDER = Comparator
			.comparing((Finding f) -> !f.blocking() || f.bypassed())
			.thenComparingInt((Finding f) -> {
				int rank = SEVERITY_ORDER.indexOf(StringUtils.defaultString(f.severity()).toUpperCase(java.util.Locale.ROOT));
				return rank < 0 ? SEVERITY_ORDER.size() : rank;
			})
			.thenComparing(Finding::path).thenComparingInt(Finding::line);

	private static Map<String, PullRequestComment> ownActive(List<PullRequestComment> comments) {
		Map<String, PullRequestComment> own = new LinkedHashMap<>();
		for (PullRequestComment comment : comments) {
			if (!comment.isInline() || comment.raw() == null) {
				continue;
			}
			Matcher marker = MARKER.matcher(comment.raw());
			if (marker.find() && marker.group(3) == null) {
				own.putIfAbsent(marker.group(1) + "-" + marker.group(2), comment);
			}
		}
		return own;
	}

	/** The comment for a finding. Package-private for tests. */
	static String text(Finding f, String ref, String link) {
		String icon = f.blocking() ? (f.bypassed() ? "✅" : "⛔") : "⚠️";
		String status = f.blocking() ? (f.bypassed() ? "blocking bypassed" : "blocking") : "not blocking";
		StringBuilder text = new StringBuilder();
		text.append(icon).append(" **").append(PRCommentFormat.escape(severityName(f.severity()))).append(" · ")
				.append(PRCommentFormat.escape(f.title())).append("** · ").append(status).append(" · AWS Security Agent\n\n");
		if (StringUtils.isNotBlank(link)) {
			text.append("[Details in the Watchtower report](").append(link).append(")\n\n");
		}
		return text.append(marker(ref, false)).toString();
	}

	private static String notReported(String oldText, String ref, String commit) {
		Matcher title = TITLE.matcher(StringUtils.defaultString(oldText));
		String heading = title.find() ? "**" + title.group(1) + "**" : "AWS finding";
		return heading + " · no longer reported by the latest AWS review"
				+ (StringUtils.isBlank(commit) ? "" : " (commit `" + PRCommentFormat.shortCommit(commit) + "`)")
				+ "\n\n" + marker(ref, true);
	}

	private static String marker(String ref, boolean notReported) {
		return "_Watchtower · aws ref " + ref + (notReported ? " · not reported" : "") + "_";
	}

	private static String severityName(String severity) {
		if (StringUtils.isBlank(severity)) {
			return "Unknown";
		}
		return severity.substring(0, 1).toUpperCase(java.util.Locale.ROOT) + severity.substring(1).toLowerCase(java.util.Locale.ROOT);
	}

	/** A stable id for a finding's comment: a hash of its title and file, then its line. */
	static String ref(Finding f) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256")
					.digest((f.title() + "\u0000" + f.path()).getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest).substring(0, REF_HASH_CHARS) + "-" + f.line();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is unavailable", e);
		}
	}
}
