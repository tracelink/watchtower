package com.tracelink.appsec.watchtower.core.scan.presentation;

/**
 * What an {@link IFindingActionProvider} knows about a pull request finding.
 *
 * @param apiLabel   the SCM integration
 * @param repoName   the repository
 * @param ruleName   the violated rule's name
 * @param filePath   the repo-relative file
 * @param lineNumber the line
 * @author Watchtower
 */
public record FindingContext(String apiLabel, String repoName, String ruleName, String filePath,
		int lineNumber) {
}
