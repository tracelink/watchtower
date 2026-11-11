package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan;

import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/**
 * Which repositories a plan scans, one token per line, resolved each time the plan runs so a
 * newly labelled or newly created repository joins automatically:
 * <ul>
 * <li>{@code *} every repository of the integration</li>
 * <li>{@code id:12} one repository, as picked in the UI</li>
 * <li>{@code label:pci}, {@code team:checkout}, {@code project:PAY}</li>
 * <li>anything else: a repository name, where {@code *} and {@code ?} are wildcards</li>
 * </ul>
 *
 * @author Watchtower
 */
public final class RepoSelector {

	public static final int MAX_TOKENS = 1_000;

	/** Every repository of the integration. */
	public static final String ALL = "*";

	/** One repository by its id, as a selection in the inventory names it. */
	public static final String ID_PREFIX = "id:";

	private static final int MAX_TOKEN_LENGTH = 255;

	private RepoSelector() {
	}

	/**
	 * @param ids repositories picked one by one
	 * @return a selector naming exactly them
	 */
	public static String ofIds(Collection<Long> ids) {
		return ids.stream().distinct().map(id -> ID_PREFIX + id)
				.collect(Collectors.joining("\n"));
	}

	/**
	 * @param selector the selector text
	 * @return its tokens, trimmed, blanks dropped
	 * @throws IllegalArgumentException if there are none, too many, or one is too long
	 */
	public static List<String> tokens(String selector) {
		List<String> tokens = Arrays.stream(StringUtils.defaultString(selector).split("\\R"))
				.map(String::trim).filter(StringUtils::isNotEmpty).distinct().toList();
		if (tokens.isEmpty()) {
			throw new IllegalArgumentException("Choose at least one repository");
		}
		if (tokens.size() > MAX_TOKENS) {
			throw new IllegalArgumentException("A plan can list at most " + MAX_TOKENS
					+ " repositories or patterns");
		}
		if (tokens.stream().anyMatch(t -> t.length() > MAX_TOKEN_LENGTH)) {
			throw new IllegalArgumentException("A repository pattern is too long");
		}
		tokens.forEach(RepoSelector::matcher);
		return tokens;
	}

	/**
	 * @param selector   the selector text
	 * @param candidates the integration's enabled repositories
	 * @return the matching repositories, most critical first, then by name
	 */
	public static List<RepositoryEntity> resolve(String selector,
			Collection<RepositoryEntity> candidates) {
		Predicate<RepositoryEntity> matches = tokens(selector).stream()
				.map(RepoSelector::matcher).reduce(r -> false, Predicate::or);
		return candidates.stream().filter(matches)
				.sorted(Comparator.comparingInt(RepositoryEntity::getCriticality)
						.thenComparing(RepositoryEntity::getRepoName,
								String.CASE_INSENSITIVE_ORDER))
				.toList();
	}

	private static Predicate<RepositoryEntity> matcher(String token) {
		if (ALL.equals(token)) {
			return r -> true;
		}
		String lower = token.toLowerCase(Locale.ROOT);
		if (lower.startsWith(ID_PREFIX)) {
			long id = parseId(token.substring(ID_PREFIX.length()));
			return r -> r.getId() == id;
		}
		if (lower.startsWith("label:")) {
			String label = lower.substring(6).trim();
			return r -> r.getLabels().contains(label);
		}
		if (lower.startsWith("team:")) {
			String team = token.substring(5).trim();
			return r -> team.equalsIgnoreCase(r.getTeam());
		}
		if (lower.startsWith("project:")) {
			String project = token.substring(8).trim();
			return r -> project.equalsIgnoreCase(r.getProjectKey());
		}
		Predicate<String> glob = glob(token);
		return r -> glob.test(r.getRepoName());
	}

	/**
	 * Matches without regular expressions, so a pattern such as {@code *a*a*a*b} cannot make
	 * matching slow: the time is at most the product of the two lengths.
	 *
	 * @param pattern a name where {@code *} matches any run of characters and {@code ?} one
	 * @return a case-insensitive test of whole names
	 */
	public static Predicate<String> glob(String pattern) {
		String glob = pattern.toLowerCase(Locale.ROOT);
		return name -> name != null && wildcardMatch(glob, name.toLowerCase(Locale.ROOT));
	}

	private static boolean wildcardMatch(String pattern, String name) {
		int p = 0;
		int n = 0;
		int star = -1;
		int resume = 0;
		while (n < name.length()) {
			if (p < pattern.length()
					&& (pattern.charAt(p) == '?' || pattern.charAt(p) == name.charAt(n))) {
				p++;
				n++;
			} else if (p < pattern.length() && pattern.charAt(p) == '*') {
				star = p++;
				resume = n;
			} else if (star >= 0) {
				// Let the last star take one more character and retry from there
				p = star + 1;
				n = ++resume;
			} else {
				return false;
			}
		}
		while (p < pattern.length() && pattern.charAt(p) == '*') {
			p++;
		}
		return p == pattern.length();
	}

	private static long parseId(String value) {
		try {
			return Long.parseLong(value.trim());
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("'" + StringUtils.abbreviate(value, 20)
					+ "' is not a repository id");
		}
	}
}
