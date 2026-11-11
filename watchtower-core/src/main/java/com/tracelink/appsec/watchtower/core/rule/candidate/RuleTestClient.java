package com.tracelink.appsec.watchtower.core.rule.candidate;

/** Execution boundary for direct engine testing now and an existing sandbox service later.
 * Adapters enforce a deadline below 120 seconds, bounded output and temporary input cleanup.
 * Execution mode/provenance must be recorded accurately; direct execution is not isolation.
 */
public interface RuleTestClient {
 boolean available();
 String executionIdentity();
 RuleTestSuite.Result test(RuleTestSuite.Request request);
 /** Deterministic directory search; adapters without it report the capability as unavailable. */
 default RuleTestSuite.SearchResult search(RuleTestSuite.SearchRequest request){throw new IllegalStateException("Repository search unavailable");}
}
