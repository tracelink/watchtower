package com.tracelink.appsec.watchtower.core.scan.code.scm.api;

/**
 * A branch of a repository and the commit at its head.
 *
 * @param name       the branch name
 * @param commitHash the full hash of the head commit
 * @param commitDate epoch millis of the head commit, 0 if unknown
 * @author Watchtower
 */
public record ScmBranch(String name, String commitHash, long commitDate) {
}
