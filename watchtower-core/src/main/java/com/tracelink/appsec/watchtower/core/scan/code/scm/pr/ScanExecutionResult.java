package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.util.concurrent.CompletableFuture;

/**
 * The outcome of
 * {@code PRScanningService.executeScan(PullRequest, IScmApi, RulesetEntity, String)}.
 * <p>
 * {@code agent} and {@code future} are null when {@code result} is
 * {@link PRScanSubmitResult#DEDUPLICATED}: no agent was built, because an identical
 * scan was already running - there is nothing for a caller to wait on.
 * <p>
 * Otherwise both are populated so a caller like {@code SqsScanConsumer} (item 4.5) can
 * defer an action (deleting the SQS message that triggered this scan) until the agent
 * actually finishes, and then check {@code agent.hasFailed()} to decide whether it
 * finished successfully - the future itself always completes normally, since
 * {@code AbstractScanAgent.run()} never lets an exception escape.
 *
 * @param result the submission outcome
 * @param agent  the scan agent that was submitted, or null if none was built
 * @param future tracks the agent's asynchronous execution, or null if none was built
 */
public record ScanExecutionResult(PRScanSubmitResult result, PRScanAgent agent,
		CompletableFuture<?> future) {
}
