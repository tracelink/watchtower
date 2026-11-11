package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;

/**
 * Keeps Watchtower's inline comments on a pull request in step with its latest scan (§4.14a):
 * one comment on the line of each new finding, edited when its status changes, replaced when the
 * finding moves, and turned into a "fixed" note (kept as history) when it is gone. Only comments
 * carrying Watchtower's footer marker are ever edited or deleted.
 *
 * @author Watchtower
 */
class PRInlineComments {

	/** New comments posted per scan; the rest are counted for the summary. */
	static final int MAX_INLINE = 50;

	/** Bitbucket refuses further comments on a pull request at this many, whoever wrote them. */
	static final int PROVIDER_COMMENT_LIMIT = 200;

	/**
	 * Comments never spent on findings, so the summary, a bypass request and its answer and the
	 * developers' own replies always fit. Without it a large pull request used the whole limit
	 * over a few rescans and `/watchtower bypass` could no longer be posted.
	 */
	static final int COMMENT_RESERVE = 25;

	private static final Logger LOG = LoggerFactory.getLogger(PRInlineComments.class);

	private static final int RULE_FILE_HASH_CHARS = 12;

	private static final int MAX_GUIDANCE_CHARS = 2000;

	private static final Pattern MARKER = Pattern.compile(
			"_Watchtower · ref ([0-9a-f]{" + RULE_FILE_HASH_CHARS + "})-(\\d+)( · resolved)?_\\s*\\z");

	private static final Pattern TITLE = Pattern.compile("\\*\\*(.+?)\\*\\*");

	private final IScmApi api;

	private final PullRequest pr;

	PRInlineComments(IScmApi api, PullRequest pr) {
		this.api = api;
		this.pr = pr;
	}

	/**
	 * @param reported      the scan's findings without MCR; only new ones are commented, but a
	 *                      pre-existing one still counts as "moved" rather than "fixed"
	 * @param appliedBypass the bypass that stopped findings blocking, or null
	 * @param commitHash    the scanned commit, named in "fixed" notes
	 * @return new findings that have no inline comment (over the cap, or the post failed)
	 */
	int sync(List<PullRequestViolationEntity> reported, ActiveBypass appliedBypass,
			String commitHash) {
		Map<String, PullRequestViolationEntity> wanted = new LinkedHashMap<>();
		reported.stream().filter(PullRequestViolationEntity::isNewViolation)
				.sorted(PRCommentFormat.ORDER).forEach(v -> wanted.putIfAbsent(ref(v), v));
		List<PullRequestComment> comments = api.listComments(pr);
		if (comments == null) {
			LOG.warn("Could not list comments of PR {}; skipping inline comments",
					pr.getPRString());
			return wanted.size();
		}
		Map<String, PullRequestComment> own = ownActiveComments(comments);
		Set<String> reportedRuleFiles = reported.stream().map(PRInlineComments::ruleFileHash)
				.collect(Collectors.toSet());
		own.forEach((ref, comment) -> {
			if (!wanted.containsKey(ref)) {
				retire(ref, comment, reportedRuleFiles, commitHash);
			}
		});
		int room = Math.max(0, PROVIDER_COMMENT_LIMIT - COMMENT_RESERVE - comments.size());
		return place(wanted, own, appliedBypass, Math.min(MAX_INLINE, room));
	}

	private int place(Map<String, PullRequestViolationEntity> wanted,
			Map<String, PullRequestComment> own, ActiveBypass appliedBypass, int allowed) {
		int posted = 0;
		int notInline = 0;
		for (Map.Entry<String, PullRequestViolationEntity> entry : wanted.entrySet()) {
			String text = text(entry.getValue(), appliedBypass);
			PullRequestComment existing = own.get(entry.getKey());
			if (existing != null) {
				if (!existing.raw().equals(text)) {
					api.updateComment(pr, existing.id(), text);
				}
			} else if (posted >= allowed) {
				notInline++;
			} else {
				posted++;
				PullRequestViolationEntity v = entry.getValue();
				if (!api.sendInlineComment(pr, v.getFileName(), v.getLineNum(), text)) {
					notInline++;
				}
			}
		}
		return notInline;
	}

	/**
	 * A comment whose finding is gone: deleted if the same rule is still reported in that file
	 * (the finding moved and gets a new comment), otherwise kept as a "fixed" note.
	 */
	private void retire(String ref, PullRequestComment comment, Set<String> reportedRuleFiles,
			String commitHash) {
		if (reportedRuleFiles.contains(StringUtils.substringBefore(ref, "-"))) {
			api.deleteComment(pr, comment.id());
			return;
		}
		Matcher title = TITLE.matcher(comment.raw());
		String what = title.find() ? title.group(1) : "this finding";
		String fixedIn = StringUtils.isBlank(commitHash) ? "Fixed"
				: "Fixed in `" + PRCommentFormat.shortCommit(commitHash) + "`";
		api.updateComment(pr, comment.id(), PRCommentFormat.BYPASSED + " **" + fixedIn
				+ "** · ~~" + what + "~~\n\n" + marker(ref, true));
	}

	/**
	 * @return Watchtower's own inline comments that are not yet resolved, by ref
	 */
	private static Map<String, PullRequestComment> ownActiveComments(
			List<PullRequestComment> comments) {
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

	/**
	 * @return the comment for a finding: status, guidance and the marker
	 */
	static String text(PullRequestViolationEntity v, ActiveBypass appliedBypass) {
		StringBuilder text = new StringBuilder();
		text.append(PRCommentFormat.icon(v)).append(" **").append(PRCommentFormat.priority(v))
				.append(" · ").append(PRCommentFormat.escape(v.getViolationName()))
				.append("** · ").append(status(v, appliedBypass)).append("\n\n");
		String guidance = StringUtils.trimToNull(v.getMessage());
		if (guidance != null) {
			text.append(StringUtils.abbreviate(guidance, MAX_GUIDANCE_CHARS)).append("\n\n");
		}
		return text.append(marker(ref(v), false)).toString();
	}

	private static String status(PullRequestViolationEntity v, ActiveBypass appliedBypass) {
		if (v.isBlocking()) {
			return "blocking";
		}
		if (v.isBypassed()) {
			return appliedBypass == null ? "blocking bypassed"
					: "blocking bypassed by " + PRCommentFormat.escape(appliedBypass.bypassedBy());
		}
		return "not blocking";
	}

	private static String marker(String ref, boolean resolved) {
		return "_Watchtower · ref " + ref + (resolved ? " · resolved" : "") + "_";
	}

	/**
	 * @return a stable id for a finding's comment: a hash of its rule and file, then its line
	 */
	static String ref(PullRequestViolationEntity v) {
		return ruleFileHash(v) + "-" + v.getLineNum();
	}

	private static String ruleFileHash(PullRequestViolationEntity v) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(
					(v.getViolationName() + "\u0000" + v.getFileName())
							.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest).substring(0, RULE_FILE_HASH_CHARS);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is unavailable", e);
		}
	}
}
