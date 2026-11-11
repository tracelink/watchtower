package com.tracelink.appsec.watchtower.core.scan.queue;

/**
 * The JSON body of an SQS scan-request message (IMPROVEMENT_PLAN.md item 4.2). Carries
 * exactly the fields {@code PRScanningService.doPullRequestScan()} needs to reconstruct
 * a {@code PullRequest} and re-run its existing lookup/dedup logic - this is not a
 * serialized {@code PullRequest} itself, since most of that object's fields (state,
 * title, timestamps) are re-fetched fresh from Bitbucket via
 * {@code api.updatePRData()} regardless of what the queue message says.
 * <p>
 * A record, not the mutable getter/setter class item 4.2's sketch in the plan shows:
 * this project's own java-coding-standards prefer records for value types, and Jackson
 * (already on the classpath as {@code com.fasterxml.jackson.databind.ObjectMapper})
 * deserializes records natively via their canonical constructor.
 *
 * @param apiLabel   the Bitbucket API integration label that owns this repo
 * @param repoName   the repository name
 * @param prId       the pull request id
 * @param commitHash the commit hash being scanned, included so a force-push is a
 *                   distinct message from the PR's prior commit
 * @param enqueuedAt epoch millis this message was published, for queue-age observability
 */
public record ScanRequestMessage(String apiLabel, String repoName, String prId, String commitHash,
		long enqueuedAt) {
}
