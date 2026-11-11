package com.tracelink.appsec.watchtower.core.scan.code.scm.api;

/**
 * A repository as listed by an SCM integration, independent of any SCM vendor. Only the
 * fields Watchtower keeps for its repository catalog are carried; no content.
 *
 * @param slug          the repository's name as used in API paths
 * @param projectKey    the SCM's grouping of repositories (a Bitbucket project), may be null
 * @param defaultBranch the main branch name, may be null for an empty repository
 * @param updatedOn     epoch millis of the SCM's last-updated time, 0 if unknown
 * @param sizeBytes     the repository size in bytes, 0 if unknown
 * @param language      the SCM's language hint, may be null
 * @author Watchtower
 */
public record ScmRepository(String slug, String projectKey, String defaultBranch,
		long updatedOn, long sizeBytes, String language) {
}
