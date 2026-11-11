package com.tracelink.appsec.watchtower.core.cwe;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.persistence.RuleHealthEntity;

/** What the stored rule health says about whether a rule runs and whether it is noisy. */
class CweRuleHealthReaderTest {
	private static final Instant NOW = Instant.parse("2026-10-27T10:00:00Z");
	private R1Database database;
	private CweRuleHealthReader reader;

	@BeforeEach
	void setUp() {
		database = new R1Database();
		reader = new CweRuleHealthReader(database.records, Clock.fixed(NOW, ZoneOffset.UTC));
	}

	@AfterEach
	void tearDown() {
		database.close();
	}

	private void store(long ruleId, String revision, Instant computedAt, String evidence) {
		database.records.insert(new RuleHealthEntity(ruleId, revision, computedAt.toEpochMilli(), evidence));
	}

	private static String evidence(long ran30, String chips90) {
		return "{\"30d\":{\"successful_engine_scans\":" + ran30 + ",\"findings\":0,\"chips\":[]},"
				+ "\"90d\":{\"successful_engine_scans\":9,\"findings\":4,\"chips\":" + chips90 + "}}";
	}

	@Test
	void aRuleWithSuccessfulScansInThirtyDaysRan() {
		store(1, "rev-a", NOW.minusSeconds(3600), evidence(3, "[]"));

		var health = reader.read(Map.of(1L, "rev-a"));

		assertThat(health.get(1L).ran()).isTrue();
		assertThat(health.get(1L).noisy()).isFalse();
	}

	@Test
	void aRuleWithNoSuccessfulScansDidNotRun() {
		store(1, "rev-a", NOW.minusSeconds(3600), evidence(0, "[]"));

		assertThat(reader.read(Map.of(1L, "rev-a")).get(1L).ran()).isFalse();
	}

	@Test
	void theNeedsReviewChipInNinetyDaysMeansNoisy() {
		store(1, "rev-a", NOW.minusSeconds(3600), evidence(5, "[\"Needs review\",\"No recent matches\"]"));

		assertThat(reader.read(Map.of(1L, "rev-a")).get(1L).noisy()).isTrue();
	}

	@Test
	void healthOfAnOlderRevisionOrOlderThanTwoDaysIsIgnored() {
		store(1, "old-rev", NOW.minusSeconds(3600), evidence(5, "[]"));
		store(2, "rev-b", NOW.minusSeconds(3 * 24 * 3600), evidence(5, "[]"));

		var health = reader.read(Map.of(1L, "new-rev", 2L, "rev-b"));

		assertThat(health).isEmpty();
	}

	@Test
	void unreadableEvidenceCountsAsNoEvidenceAndAMissingRevisionMatchesUnknown() {
		store(1, "rev-a", NOW.minusSeconds(60), "not json");
		store(2, "unknown", NOW.minusSeconds(60), evidence(2, "[]"));
		java.util.Map<Long, String> revisions = new java.util.HashMap<>();
		revisions.put(1L, "rev-a");
		revisions.put(2L, null);

		var health = reader.read(revisions);

		assertThat(health).doesNotContainKey(1L);
		assertThat(health.get(2L).ran()).isTrue();
	}

	@Test
	void manyRulesAreReadInChunks() {
		var revisions = new java.util.HashMap<Long, String>();
		for (long id = 1; id <= 1200; id++) {
			revisions.put(id, "r");
			if (id % 300 == 0) {
				store(id, "r", NOW.minusSeconds(60), evidence(1, "[]"));
			}
		}

		assertThat(reader.read(revisions).keySet()).containsExactlyInAnyOrder(300L, 600L, 900L, 1200L);
	}

	@Test
	void noRulesMeansNoQuery() {
		assertThat(reader.read(Map.of())).isEmpty();
	}
}
