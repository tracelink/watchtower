package com.tracelink.appsec.watchtower.core.rule;

/** Human-managed lifecycle. Deprecated rules continue to run until explicitly retired. */
public enum RuleState {
	ACTIVE, DEPRECATED, RETIRED
}
