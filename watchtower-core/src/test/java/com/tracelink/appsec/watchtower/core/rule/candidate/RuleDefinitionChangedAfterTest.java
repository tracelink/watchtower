package com.tracelink.appsec.watchtower.core.rule.candidate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.persistence.RuleDefinitionVersionEntity;

/**
 * Dev E2E G03: a report read the rule's current guidance, so editing a rule changed what an old report
 * said. A report can only say "this rule changed since the scan" if the history can answer that.
 */
class RuleDefinitionChangedAfterTest {

	private static final long RULE = 1720L;

	private static final long SCAN = 1_000_000L;

	private R1Database database;

	private RuleDefinitionHistory history;

	@BeforeEach
	void setUp() {
		database = new R1Database();
		history = database.service(new RuleDefinitionHistory(database.records));
	}

	@AfterEach
	void tearDown() {
		database.close();
	}

	private void observed(long ruleId, String hash, long at) {
		database.records.insert(new RuleDefinitionVersionEntity(UUID.randomUUID().toString(), ruleId,
				"rev-" + hash, hash, "Regex", "{}", "tester", at));
	}

	@Test
	void aDefinitionObservedBeforeAndAfterTheScanMeansTheRuleChanged() {
		observed(RULE, "a", SCAN - 500);
		observed(RULE, "b", SCAN + 500);

		assertTrue(history.changedAfter(RULE, SCAN));
	}

	@Test
	void aRuleOnlyObservedAfterTheScanIsNotSaidToHaveChanged() {
		// The first observation is a baseline taken when history began, not an edit.
		observed(RULE, "a", SCAN + 500);

		assertFalse(history.changedAfter(RULE, SCAN));
	}

	@Test
	void aRuleNotObservedAfterTheScanHasNotChanged() {
		observed(RULE, "a", SCAN - 500);

		assertFalse(history.changedAfter(RULE, SCAN));
	}

	@Test
	void anotherRulesChangesDoNotCount() {
		observed(RULE, "a", SCAN - 500);
		observed(RULE + 1, "x", SCAN - 500);
		observed(RULE + 1, "y", SCAN + 500);

		assertFalse(history.changedAfter(RULE, SCAN));
	}
}
