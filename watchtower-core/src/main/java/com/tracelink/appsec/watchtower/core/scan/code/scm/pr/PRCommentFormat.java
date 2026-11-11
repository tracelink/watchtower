package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.util.Comparator;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;

/**
 * What the PR summary comment and the inline comments share: finding order, status icons and
 * markdown escaping (§4.14).
 *
 * @author Watchtower
 */
public final class PRCommentFormat {

	static final String BLOCKING = "⛔";
	static final String BYPASSED = "✅";
	static final String NOT_BLOCKING = "⚠️";

	/** Blocking first, then by priority (highest first), file and line. */
	static final Comparator<PullRequestViolationEntity> ORDER = Comparator
			.comparing((PullRequestViolationEntity v) -> !v.isBlocking())
			.thenComparing(PullRequestViolationEntity::getSeverity,
					Comparator.nullsLast(Comparator.comparingInt(RulePriority::getPriority)))
			.thenComparing(PullRequestViolationEntity::getFileName,
					Comparator.nullsLast(Comparator.naturalOrder()))
			.thenComparingInt(PullRequestViolationEntity::getLineNum);

	private static final String MARKDOWN_SPECIAL = "\\`*_[]|<>";

	private PRCommentFormat() {
	}

	static String icon(PullRequestViolationEntity v) {
		if (v.isBlocking()) {
			return BLOCKING;
		}
		return v.isBypassed() ? BYPASSED : NOT_BLOCKING;
	}

	static String priority(PullRequestViolationEntity v) {
		return v.getSeverity() == null ? "Unknown" : v.getSeverity().getName();
	}

	/**
	 * @return the text on one line with markdown control characters escaped, so a rule name or
	 *         path can't break a table or add formatting
	 */
	public static String escape(String text) {
		String oneLine = StringUtils.normalizeSpace(StringUtils.defaultString(text));
		StringBuilder escaped = new StringBuilder(oneLine.length());
		for (char c : oneLine.toCharArray()) {
			if (MARKDOWN_SPECIAL.indexOf(c) >= 0) {
				escaped.append('\\');
			}
			escaped.append(c);
		}
		return escaped.toString();
	}

	/**
	 * Free text a user wrote (a bypass reason), for a PR comment posted under Watchtower's name.
	 * As an inline code span it renders literally: no links, formatting or autolinked URLs, so
	 * anyone who may request a bypass cannot make Watchtower post a convincing link.
	 *
	 * @return the text on one line, in a code span
	 */
	public static String quote(String text) {
		return "`" + StringUtils.normalizeSpace(StringUtils.defaultString(text)).replace('`', '\'')
				+ "`";
	}

	/**
	 * @return {@code file:line}, as code when the path allows it
	 */
	static String location(PullRequestViolationEntity v) {
		String path = StringUtils.defaultString(v.getFileName());
		if (StringUtils.containsAny(path, "`|") || StringUtils.containsWhitespace(path)) {
			return escape(path) + ":" + v.getLineNum();
		}
		return "`" + path + ":" + v.getLineNum() + "`";
	}

	static String shortCommit(String commitHash) {
		return StringUtils.left(commitHash, 7);
	}
}
