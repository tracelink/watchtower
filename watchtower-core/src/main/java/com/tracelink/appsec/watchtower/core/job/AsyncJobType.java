package com.tracelink.appsec.watchtower.core.job;

/**
 * Long-running work done off the request thread, through the queue.
 *
 * @author Watchtower
 */
public enum AsyncJobType {
	CATALOG_SYNC("Repository sync"), EXPAND_PLAN("Prepare scan run"), EXPORT_RUN("Export run"),
	INTEGRATION_HEALTH("Integration check"), RULE_CANDIDATE_TEST("Test rule candidate"),
	VARIANT_SEARCH("Search other repositories"), UPSTREAM_CHECK("Check upstream rule update"),
	ASSISTANT_EVALUATION("Assistant answer evaluation"), AI_BATCH_TRIAGE("AI batch triage"),
	/** Stored by ordinal: always add new types at the end. */
	CWE_CATALOG_REFRESH("CWE catalog update"), AI_CODE_REVIEW("AI code review"), WEBHOOK_SYNC("Refresh webhooks"), WEBHOOK_BULK("Manage webhooks");

	private final String displayName;

	AsyncJobType(String displayName) {
		this.displayName = displayName;
	}

	public String getDisplayName() {
		return displayName;
	}
}
