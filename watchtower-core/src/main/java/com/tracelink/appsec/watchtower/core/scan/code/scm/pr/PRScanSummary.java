package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRCommentCommand;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;

/**
 * The summary comment posted on a pull request after each scan (§4.14a): a status headline,
 * counts, a table of new findings, a table of pre-existing ones, notes (bypass, incomplete scan)
 * and a link to the full report. The guidance for each finding is in its inline comment.
 *
 * @param findings           the findings to report; MCR findings must already be left out
 * @param incompleteScanners display names of scanners that reported errors, so did not finish
 * @param appliedBypass      the bypass that stopped a finding blocking, or null
 * @param notInline          new findings that could not be commented on their line
 * @param commitHash         the scanned commit, or null
 * @param reportLink         the Watchtower report, or null when no public URL is configured
 * @param bypassRequestable  whether a blocked pull request stays open, so the summary may tell
 *                           its developer how to ask for a bypass (§4.18)
 * @param remote             what a remote review (AWS) returned, shown as one line, or null when
 *                           the scan has none
 * @author Watchtower
 */
record PRScanSummary(List<PullRequestViolationEntity> findings,
		Collection<String> incompleteScanners, ActiveBypass appliedBypass, int notInline,
		String commitHash, String reportLink, boolean bypassRequestable,
		PRStatusComment.Remote remote) {

	PRScanSummary(List<PullRequestViolationEntity> findings,
			Collection<String> incompleteScanners, ActiveBypass appliedBypass, int notInline,
			String commitHash, String reportLink, boolean bypassRequestable) {
		this(findings, incompleteScanners, appliedBypass, notInline, commitHash, reportLink,
				bypassRequestable, null);
	}

	PRScanSummary(List<PullRequestViolationEntity> findings,
			Collection<String> incompleteScanners, ActiveBypass appliedBypass, int notInline,
			String commitHash, String reportLink) {
		this(findings, incompleteScanners, appliedBypass, notInline, commitHash, reportLink,
				false, null);
	}

	/** Rows per table; the rest are counted and left to the full report. */
	static final int MAX_ROWS = 50;

	private static final String CONTACT = "Questions: #security-team · security@example.com";

	String toMarkdown() {
		List<PullRequestViolationEntity> newFindings = findings.stream()
				.filter(PullRequestViolationEntity::isNewViolation).sorted(PRCommentFormat.ORDER)
				.toList();
		List<PullRequestViolationEntity> preExisting = findings.stream()
				.filter(v -> !v.isNewViolation()).sorted(PRCommentFormat.ORDER).toList();

		List<String> lines = new ArrayList<>();
		lines.add("### 🛡️ Watchtower — " + headline(newFindings));
		lines.add("");
		lines.add(counts(newFindings, preExisting));
		if (remote != null) {
			lines.add("");
			lines.add(remote.line());
			addRemoteRows(lines);
		}
		if (!newFindings.isEmpty()) {
			lines.add("");
			lines.add("| Priority | Rule | Where |");
			lines.add("|---|---|---|");
			addRows(lines, newFindings, v -> cells(PRCommentFormat.icon(v) + " ", v));
		}
		if (!preExisting.isEmpty()) {
			lines.add("");
			lines.add("**Pre-existing (" + preExisting.size() + ", not blocking)**");
			lines.add("");
			lines.add("| Priority | Rule | Where |");
			lines.add("|---|---|---|");
			addRows(lines, preExisting, v -> cells(v));
		}
		notes(newFindings).forEach(note -> {
			lines.add("");
			lines.add(note);
		});
		lines.add("");
		lines.add(footer(!newFindings.isEmpty()));
		return String.join("\n", lines);
	}

	/** The top AWS findings, with how many there are in all when the rest are left to the report. */
	private void addRemoteRows(List<String> lines) {
		List<PRStatusComment.Row> rows = remote.rows();
		if (rows.isEmpty()) {
			return;
		}
		int shown = Math.min(rows.size(), PRStatusComment.Remote.MAX_ROWS);
		int total = remote.findings() == null ? rows.size() : Math.max(remote.findings(), rows.size());
		lines.add("");
		lines.add(total > shown ? "**AWS findings: top " + shown + " of " + total + "**" : "**AWS findings**");
		lines.add("");
		lines.add("| Priority | Finding | Where |");
		lines.add("|---|---|---|");
		for (PRStatusComment.Row row : rows.subList(0, shown)) {
			String icon = row.blocking() ? (row.bypassed() ? PRCommentFormat.BYPASSED : PRCommentFormat.BLOCKING)
					: PRCommentFormat.NOT_BLOCKING;
			lines.add("| " + icon + " " + PRCommentFormat.escape(row.priority()) + " | "
					+ PRCommentFormat.escape(row.title()) + " | " + where(row) + " |");
		}
		if (total > shown) {
			lines.add("");
			lines.add("…and " + (total - shown) + " more in the "
					+ (reportLink == null ? "full report" : "[full report](" + reportLink + ")") + ".");
		}
	}

	private static String where(PRStatusComment.Row row) {
		String path = StringUtils.defaultString(row.file());
		if (path.isEmpty()) {
			return "—";
		}
		if (StringUtils.containsAny(path, "`|") || StringUtils.containsWhitespace(path)) {
			return PRCommentFormat.escape(path) + ":" + row.line();
		}
		return "`" + path + ":" + row.line() + "`";
	}

	private String headline(List<PullRequestViolationEntity> newFindings) {
		if (newFindings.stream().anyMatch(PullRequestViolationEntity::isBlocking)
				|| remote != null && remote.blocking() > 0) {
			return PRCommentFormat.BLOCKING + " Blocking issues found";
		}
		if (newFindings.stream().anyMatch(PullRequestViolationEntity::isBypassed)) {
			return PRCommentFormat.BYPASSED + " Blocking bypassed";
		}
		if (newFindings.isEmpty() && (remote == null || remote.noFindings())) {
			// A scanner that did not finish may have found something: never a check mark
			return incompleteScanners.isEmpty() ? "✅ No new issues" : "⚠️ Scan incomplete";
		}
		return PRCommentFormat.NOT_BLOCKING + " New issues, none blocking";
	}

	private String counts(List<PullRequestViolationEntity> newFindings,
			List<PullRequestViolationEntity> preExisting) {
		if (newFindings.isEmpty() && preExisting.isEmpty()) {
			if (!incompleteScanners.isEmpty()) {
				return "No issues found by the scanners that finished, in the changed files.";
			}
			return remote == null ? "No issues found in the changed files."
					: "No issues from Watchtower's scanners in the changed files.";
		}
		StringBuilder counts = new StringBuilder();
		if (newFindings.isEmpty()) {
			counts.append("**No new issues**");
		} else {
			long blocking = newFindings.stream().filter(PullRequestViolationEntity::isBlocking)
					.count();
			long bypassed = newFindings.stream().filter(PullRequestViolationEntity::isBypassed)
					.count();
			counts.append("**").append(plural(newFindings.size(), "new issue"));
			if (blocking > 0) {
				counts.append(" (").append(blocking).append(" blocking)");
			} else if (bypassed > 0) {
				counts.append(" (").append(bypassed).append(" bypassed)");
			}
			counts.append("**");
		}
		if (!preExisting.isEmpty()) {
			counts.append(" · ").append(preExisting.size()).append(" pre-existing");
		}
		if (StringUtils.isNotBlank(commitHash)) {
			counts.append(" · commit `").append(PRCommentFormat.shortCommit(commitHash))
					.append('`');
		}
		return counts.toString();
	}

	private void addRows(List<String> lines, List<PullRequestViolationEntity> rows,
			Function<PullRequestViolationEntity, String> row) {
		rows.stream().limit(MAX_ROWS).map(row).forEach(lines::add);
		if (rows.size() > MAX_ROWS) {
			lines.add("");
			lines.add("…and " + (rows.size() - MAX_ROWS) + " more in the "
					+ (reportLink == null ? "full report" : "[full report](" + reportLink + ")")
					+ ".");
		}
	}

	private static String cells(PullRequestViolationEntity v) {
		return cells("", v);
	}

	/** One table row; the icon, when there is one, shares the priority cell so it needs no column of its own. */
	private static String cells(String icon, PullRequestViolationEntity v) {
		return "| " + icon + PRCommentFormat.priority(v) + " | " + PRCommentFormat.escape(
				v.getViolationName()) + " | " + PRCommentFormat.location(v) + " |";
	}

	private List<String> notes(List<PullRequestViolationEntity> newFindings) {
		List<String> notes = new ArrayList<>();
		if (appliedBypass != null) {
			notes.add("> ✅ **Blocking bypassed by " + PRCommentFormat.escape(
					appliedBypass.bypassedBy()) + ":** " + PRCommentFormat.quote(
							appliedBypass.reason()) + ". New blocking findings still block.");
		}
		if (bypassRequestable
				&& newFindings.stream().anyMatch(PullRequestViolationEntity::isBlocking)) {
			notes.add("> 💬 To ask for a bypass, comment `" + PRCommentCommand.BYPASS_SYNTAX
					+ "`.");
		}
		if (!incompleteScanners.isEmpty()) {
			notes.add("> ⚠️ **Scan incomplete:** " + String.join(", ", incompleteScanners)
					+ " did not finish, so findings may be missing. Push again to rescan.");
		}
		if (notInline > 0) {
			notes.add("> ℹ️ " + plural(notInline, "finding")
					+ " could not be commented on their line.");
		}
		return notes;
	}

	private String footer(boolean hasNewFindings) {
		List<String> parts = new ArrayList<>();
		if (hasNewFindings) {
			parts.add("Details are on each line");
		}
		if (reportLink != null) {
			parts.add("[Full report](" + reportLink + ")");
		}
		parts.add(CONTACT);
		return String.join(" · ", parts);
	}

	private static String plural(long count, String noun) {
		return count + " " + noun + (count == 1 ? "" : "s");
	}
}
