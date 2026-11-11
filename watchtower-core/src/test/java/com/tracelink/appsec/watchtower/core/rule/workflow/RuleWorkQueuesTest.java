package com.tracelink.appsec.watchtower.core.rule.workflow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.ormfixtures.PersistedTestRule;

/**
 * The five Rule work queues over real rows: which rules land where, in what order, and how many. It pins the
 * behaviour so the way the queries are built can change without changing what people see.
 */
class RuleWorkQueuesTest {
	private static final String R1 = "r1";

	private R1Database database;
	private RuleWorkService work;
	private long now;

	@BeforeEach
	void setUp() {
		database = new R1Database();
		now = System.currentTimeMillis();
		RuleHealthService health = mock(RuleHealthService.class);
		when(health.minimumSample()).thenReturn(5);
		when(health.minimumFalsePositives()).thenReturn(3);
		when(health.falsePositiveRate()).thenReturn(0.5);
		RuleService rules = mock(RuleService.class);
		when(rules.moduleOfType(any())).thenReturn("test");
		when(rules.ruleTypesOfModule("test")).thenReturn(List.of(PersistedTestRule.class));
		when(rules.ruleTypesOfModule("nothing")).thenReturn(List.of());
		work = new RuleWorkService(database.records, health, mock(RuleWorkLinks.class), rules);
		seed();
	}

	@AfterEach
	void tearDown() {
		database.close();
	}

	private void rule(long id, String name, String owner, String cwe, String relevance, LocalDate reviewBy) {
		database.seedRule(id, R1);
		database.jdbc.update("UPDATE rules SET name=?, rule_owner=?, cwe=?, security_relevance=?, review_by=? WHERE rule_id=?", name,
				owner, cwe, relevance, reviewBy, id);
	}

	private void metric(long scanId, long ruleId, long findings, String engineStatus) {
		database.jdbc.update("INSERT INTO rule_metric_scan(scan_type,scan_id,identity_key,rule_id,revision,module,bucket_start,findings,"
				+ "blocking,blocking_unknown,coverage,engine_status) VALUES ('pull_request',?,?,?,?,'test',?,?,0,0,'FULL',?)", scanId,
				"k" + scanId + "-" + ruleId, ruleId, R1, now, findings, engineStatus);
	}

	private void judgment(String key, long scanId, long ruleId, String judgment) {
		database.jdbc.update("INSERT INTO finding_feedback(occurrence_key,scan_type,scan_id,finding_key,rule_id,revision,occurred_at,"
				+ "judgment,disposition,explanation,reviewer,updated_at,version) VALUES (?, 'pull_request',?,?,?,?,?,?,'NONE','x','sam',?,0)", key,
				scanId, key, ruleId, R1, now, judgment, now);
	}

	private void candidate(String id, long ruleId, String status, long updatedAt) {
		database.jdbc.update("INSERT INTO rule_candidates(candidate_id,rule_id,base_revision,base_definition_hash,revision,definition_json,"
				+ "status,rationale,reviewer,created_at,updated_at,version) VALUES (?,?,?,?,?,?,?,?,?,?,?,0)", id, ruleId, R1, "h", "r2", "{}",
				status, "tighten it", "sam", updatedAt, updatedAt);
	}

	private void seed() {
		LocalDate yesterday = LocalDate.now(ZoneOffset.UTC).minusDays(1);
		rule(101, "alpha-noisy", "team-a", "CWE-79", null, null);
		rule(102, "bravo-fewreviews", "team-a", "CWE-80", null, null);
		rule(103, "charlie-unknown", "team-b", "CWE-81", null, null);
		rule(104, "delta-quiet", null, null, null, null);
		rule(105, "echo-style", "team-a", null, "NOT_SECURITY", null);
		rule(106, "foxtrot-due", "team-c", "CWE-82", null, yesterday);
		rule(107, "golf-pending", "team-c", "CWE-83", null, null);
		rule(108, "hotel-clean", "team-a", "CWE-84", null, null);
		rule(109, "india-nocwe", "team-a", null, null, null);

		metric(1, 101, 10, "RAN");
		for (int i = 0; i < 6; i++) {
			judgment("fp" + i, 1, 101, "FALSE_POSITIVE");
		}
		for (int i = 0; i < 2; i++) {
			judgment("tp" + i, 1, 101, "TRUE_POSITIVE");
		}
		metric(2, 102, 5, "RAN");
		judgment("few0", 2, 102, "TRUE_POSITIVE");
		judgment("few1", 2, 102, "TRUE_POSITIVE");
		metric(3, 103, 1, "RAN");
		judgment("unk0", 3, 103, "UNKNOWN");
		metric(4, 104, 0, "RAN");

		database.jdbc.update("INSERT INTO rule_review_items(review_id,rule_id,revision,owner,status,reason,recommendation,outcome,"
				+ "created_at,updated_at,version) VALUES ('rv1',107,?,'team-c','OPEN','noise','tune it','none',?,?,0)", R1, now, now);
		candidate("c1", 101, "DRAFT", now - 5_000);
		candidate("c2", 102, "SHADOW", now - 1_000);
		candidate("c3", 103, "REJECTED", now);
	}

	private RuleWorkService.Filter filter(String search, String owner, String gap, String scanner, boolean scans, boolean modify) {
		return new RuleWorkService.Filter(search, owner, false, 30, gap, scans, modify, scanner);
	}

	private RuleWorkService.Filter all() {
		return filter("", "", "all", "all", true, true);
	}

	private List<Long> ids(String queue, RuleWorkService.Filter filter) {
		return work.queue(queue, filter, 0, 25).content().stream().map(RuleWorkService.WorkItem::ruleId).toList();
	}

	@Test
	void reviewListsRulesWithTooFewReviewsOrAnUnknownJudgmentMostMatchesFirst() {
		assertThat(ids("review", all())).containsExactly(102L, 103L);
	}

	@Test
	void investigateListsRulesWhoseReviewedFindingsAreMostlyFalsePositives() {
		assertThat(ids("investigate", all())).containsExactly(101L);
	}

	@Test
	void reviewsListsTheOverdueRuleBeforeTheOneWithAnOpenReview() {
		assertThat(ids("reviews", all())).containsExactly(106L, 107L);
	}

	@Test
	void candidatesListsDraftAndShadowNewestFirstAndOnlyForPeopleWhoCanModify() {
		assertThat(ids("candidates", all())).containsExactly(102L, 101L);
		assertThat(ids("candidates", filter("", "", "all", "all", true, false))).isEmpty();
	}

	@Test
	void setupListsEachGapAndLeavesOutNotASecurityRulesAndCleanRules() {
		assertThat(ids("setup", all())).containsExactly(104L, 109L);
		assertThat(ids("setup", filter("", "", "cwe", "all", true, true))).containsExactly(104L, 109L);
		assertThat(ids("setup", filter("", "", "owner", "all", true, true))).containsExactly(104L);
		assertThat(ids("setup", filter("", "", "nomatches", "all", true, true))).containsExactly(104L);
	}

	@Test
	void setupWithoutScanAccessNeverListsTheScanBasedGap() {
		assertThat(ids("setup", filter("", "", "nomatches", "all", false, true))).isEmpty();
		assertThat(ids("setup", filter("", "", "all", "all", false, true))).containsExactly(104L, 109L);
	}

	@Test
	void scanQueuesAreEmptyForSomeoneWhoCannotSeeScans() {
		assertThat(ids("review", filter("", "", "all", "all", false, true))).isEmpty();
		assertThat(ids("investigate", filter("", "", "all", "all", false, true))).isEmpty();
	}

	@Test
	void theSearchAndOwnerFiltersNarrowEveryQueue() {
		assertThat(ids("review", filter("bravo", "", "all", "all", true, true))).containsExactly(102L);
		assertThat(ids("review", filter("", "team-b", "all", "all", true, true))).containsExactly(103L);
		assertThat(ids("reviews", filter("", "team-c", "all", "all", true, true))).containsExactly(106L, 107L);
		assertThat(ids("setup", filter("", "team-a", "all", "all", true, true))).containsExactly(109L);
		assertThat(ids("setup", filter("india", "", "all", "all", true, true))).containsExactly(109L);
	}

	@Test
	void aSearchWithWildcardCharactersIsTakenLiterally() {
		assertThat(ids("setup", filter("%", "", "all", "all", true, true))).isEmpty();
		assertThat(ids("setup", filter("_", "", "all", "all", true, true))).isEmpty();
		assertThat(ids("setup", filter("a'; DROP TABLE rules; --", "", "all", "all", true, true))).isEmpty();
		assertThat(ids("setup", all())).containsExactly(104L, 109L);
	}

	@Test
	void theExactOwnerFilterDoesNotMatchALongerName() {
		var exactTeam = new RuleWorkService.Filter("", "team", true, 30, "all", true, true, "all");
		assertThat(ids("setup", exactTeam)).isEmpty();
		var exactA = new RuleWorkService.Filter("", "team-a", true, 30, "all", true, true, "all");
		assertThat(ids("setup", exactA)).containsExactly(109L);
	}

	@Test
	void theScannerFilterKeepsOneModuleAndAnUnknownModuleKeepsNothing() {
		assertThat(ids("setup", filter("", "", "all", "test", true, true))).containsExactly(104L, 109L);
		assertThat(ids("setup", filter("", "", "all", "nothing", true, true))).isEmpty();
	}

	@Test
	void pagingReportsTheTotalAndSlicesTheRows() {
		var first = work.queue("setup", all(), 0, 1);
		var second = work.queue("setup", all(), 1, 1);

		assertThat(first.totalElements()).isEqualTo(2);
		assertThat(first.content()).extracting(RuleWorkService.WorkItem::ruleId).containsExactly(104L);
		assertThat(second.content()).extracting(RuleWorkService.WorkItem::ruleId).containsExactly(109L);
	}

	@Test
	void everyQueueCountsTheSameRowsItLists() {
		Map<String, Long> counts = work.counts(all(), "none", 0);

		assertThat(counts).containsEntry("review", 2L).containsEntry("investigate", 1L).containsEntry("reviews", 2L)
				.containsEntry("candidates", 2L).containsEntry("setup", 2L);
	}

	@Test
	void countsAreNullForQueuesTheViewerCannotSee() {
		Map<String, Long> counts = work.counts(filter("", "", "all", "all", false, false), "none", 0);

		assertThat(counts.get("review")).isNull();
		assertThat(counts.get("investigate")).isNull();
		assertThat(counts.get("candidates")).isNull();
		assertThat(counts.get("reviews")).isEqualTo(2L);
	}

	@Test
	void reviewAndInvestigateItemsCarryTheirNumbers() {
		var review = work.queue("review", all(), 0, 25).content();
		var investigate = work.queue("investigate", all(), 0, 25).content();

		assertThat(review.get(0).evidence()).contains("5 matches").contains("2 reviewed");
		assertThat(review.get(1).evidence()).contains("1 marked Unknown");
		assertThat(investigate.get(0).evidence()).contains("6 of 8 reviewed findings are false positives");
	}
}
