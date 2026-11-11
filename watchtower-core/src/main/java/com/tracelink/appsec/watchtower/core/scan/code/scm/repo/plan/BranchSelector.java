package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmBranch;

/**
 * Which branches of each repository a plan scans: blank for the repository's default branch,
 * else comma separated names, where a name containing {@code *} or {@code ?} is a pattern
 * matched against the repository's branches (for example {@code main, release/*}).
 *
 * @author Watchtower
 */
public final class BranchSelector {

	public static final int MAX_LENGTH = 512;

	private static final int LISTED_PER_PATTERN = 100;

	private BranchSelector() {
	}

	/**
	 * @param selector the branch selector text
	 * @throws IllegalArgumentException if it is too long or has an unusable name
	 */
	public static void validate(String selector) {
		if (StringUtils.length(selector) > MAX_LENGTH) {
			throw new IllegalArgumentException("The branch list is too long");
		}
		for (String name : tokens(selector)) {
			if (name.contains("..") || name.startsWith("/") || name.contains(" ")) {
				throw new IllegalArgumentException("'" + StringUtils.abbreviate(name, 40)
						+ "' is not a branch name or pattern");
			}
		}
	}

	/**
	 * @param selector      the branch selector text
	 * @param defaultBranch the repository's default branch, may be null
	 * @param api           lists branches when a pattern is used
	 * @param repository    the repository name
	 * @param max           the most branches to return
	 * @return the branch names to scan, at most {@code max}; empty if none apply
	 */
	public static List<String> resolve(String selector, String defaultBranch, IScmApi api,
			String repository, int max) {
		List<String> tokens = tokens(selector);
		if (tokens.isEmpty()) {
			return StringUtils.isBlank(defaultBranch) ? List.of() : List.of(defaultBranch);
		}
		Set<String> branches = new LinkedHashSet<>();
		for (String token : tokens) {
			if (branches.size() >= max) {
				break;
			}
			if (!isPattern(token)) {
				branches.add(token);
				continue;
			}
			Predicate<String> pattern = RepoSelector.glob(token);
			String literal = StringUtils.substringBefore(StringUtils.substringBefore(token, "*"),
					"?");
			api.listBranches(repository, literal, LISTED_PER_PATTERN).stream()
					.map(ScmBranch::name).filter(pattern)
					.forEach(branches::add);
		}
		return branches.stream().limit(max).toList();
	}

	private static List<String> tokens(String selector) {
		return Arrays.stream(StringUtils.defaultString(selector).split(",")).map(String::trim)
				.filter(StringUtils::isNotEmpty).distinct().toList();
	}

	private static boolean isPattern(String token) {
		return token.contains("*") || token.contains("?");
	}
}
