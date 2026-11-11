package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

/**
 * How many bypasses one repository had in a period, for the bypass audit page.
 *
 * @param apiLabel the SCM integration
 * @param repoName the repository
 * @param count    bypasses made in the period, revoked or not
 * @author Watchtower
 */
public record RepoBypassCount(String apiLabel, String repoName, long count) {
}
