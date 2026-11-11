package com.tracelink.appsec.module.betterleaks.allowlist;

/**
 * An active allowlist entry as a scan applies it. At least one of {@code pathGlob} and
 * {@code ruleId} is set:
 * <ul>
 * <li>path only - no rule reports in matching files;</li>
 * <li>rule only - the rule does not run;</li>
 * <li>both - that rule does not report in matching files.</li>
 * </ul>
 *
 * @param scope    where the entry applies
 * @param repoName the repository, for {@link BetterleaksAllowlistScope#REPO}
 * @param pathGlob the repository-relative path glob, or null
 * @param ruleId   the Betterleaks rule id, or null
 * @author Watchtower
 */
public record BetterleaksAllowlistEntry(BetterleaksAllowlistScope scope, String repoName,
		String pathGlob, String ruleId) {
}
