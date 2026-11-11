package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

/**
 * A comment on a pull request, as the SCM returned it.
 *
 * @param id   the SCM's comment id
 * @param raw  its text, as written (markdown)
 * @param path the file of an inline comment, or null for a PR-level comment
 * @param line the line in the new version of that file, or null if not on a line
 * @author Watchtower
 */
public record PullRequestComment(long id, String raw, String path, Integer line) {

	/**
	 * @return true if the comment is anchored to a line of a file
	 */
	public boolean isInline() {
		return path != null && line != null;
	}
}
