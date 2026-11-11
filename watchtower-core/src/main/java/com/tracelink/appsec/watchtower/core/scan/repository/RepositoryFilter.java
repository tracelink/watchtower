package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.apache.commons.lang3.StringUtils;

/**
 * What the repository inventory is filtered by. The search box takes a name and, optionally,
 * the plan selector's {@code label:}, {@code team:} and {@code project:} tokens separated by
 * spaces, e.g. {@code pay label:pci team:checkout}.
 *
 * @param text     part of the repository name, case-insensitive; empty for any
 * @param status   one status, or null for any
 * @param label    one label (stored lower-case), or null for any
 * @param team     the owning team, case-insensitive, or null for any
 * @param project  the SCM project key, case-insensitive, or null for any
 * @param coverage how lately a repository scan covered it, or null for any
 * @author Watchtower
 */
public record RepositoryFilter(String text, RepoStatus status, String label, String team,
		String project, RepoCoverage coverage) {

	/** The longest search the inventory accepts; longer input is cut. */
	public static final int MAX_SEARCH = 200;

	private static final int MAX_VALUE = 128;

	public static final RepositoryFilter NONE =
			new RepositoryFilter("", null, null, null, null, null);

	public RepositoryFilter {
		text = StringUtils.left(StringUtils.trimToEmpty(text), MAX_VALUE);
		label = StringUtils.isBlank(label) ? null
				: StringUtils.left(label.trim().toLowerCase(Locale.ROOT), MAX_VALUE);
		team = StringUtils.isBlank(team) ? null : StringUtils.left(team.trim(), MAX_VALUE);
		project = StringUtils.isBlank(project) ? null
				: StringUtils.left(project.trim(), MAX_VALUE);
	}

	/**
	 * @param search the search box, e.g. {@code pay label:pci}
	 * @param status a status key from {@link RepoStatus#getKey()}, blank for any
	 * @param label  a label chosen from the label menu; wins over a {@code label:} token
	 * @return the filter
	 */
	public static RepositoryFilter of(String search, String status, String label) {
		return of(search, status, label, null);
	}

	/**
	 * @param search   the search box, e.g. {@code pay label:pci}
	 * @param status   a status key from {@link RepoStatus#getKey()}, blank for any
	 * @param label    a label chosen from the label menu; wins over a {@code label:} token
	 * @param coverage a key from {@link RepoCoverage#getKey()}, blank for any
	 * @return the filter
	 */
	public static RepositoryFilter of(String search, String status, String label,
			String coverage) {
		List<String> words = new ArrayList<>();
		String tokenLabel = null;
		String team = null;
		String project = null;
		for (String word : StringUtils.left(StringUtils.defaultString(search), MAX_SEARCH)
				.trim().split("\\s+")) {
			String lower = word.toLowerCase(Locale.ROOT);
			if (lower.startsWith("label:")) {
				tokenLabel = word.substring(6);
			} else if (lower.startsWith("team:")) {
				team = word.substring(5);
			} else if (lower.startsWith("project:")) {
				project = word.substring(8);
			} else if (!word.isEmpty()) {
				words.add(word);
			}
		}
		return new RepositoryFilter(String.join(" ", words),
				RepoStatus.fromKey(status).orElse(null),
				StringUtils.isNotBlank(label) ? label : tokenLabel, team, project,
				RepoCoverage.fromKey(coverage).orElse(null));
	}

	/** @return true if nothing narrows the list */
	public boolean isEmpty() {
		return text.isEmpty() && status == null && label == null && team == null
				&& project == null && coverage == null;
	}

	/** @return the same filter with another status */
	public RepositoryFilter withStatus(RepoStatus other) {
		return new RepositoryFilter(text, other, label, team, project, coverage);
	}

	/** @return the same filter with another coverage */
	public RepositoryFilter withCoverage(RepoCoverage other) {
		return new RepositoryFilter(text, status, label, team, project, other);
	}
}
