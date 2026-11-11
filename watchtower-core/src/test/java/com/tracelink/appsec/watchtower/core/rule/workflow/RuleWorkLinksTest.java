package com.tracelink.appsec.watchtower.core.rule.workflow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.assistant.R1Database;

/** The "Review findings" links on Rule work must open a report that exists. */
class RuleWorkLinksTest {
	private static final String REVISION = "r1";
	private static final long RULE = 101;

	private R1Database database;
	private RuleWorkLinks links;
	private long now;

	@BeforeEach
	void setUp() {
		database = new R1Database();
		now = System.currentTimeMillis();
		database.seedRule(RULE, REVISION);
		links = database.service(new RuleWorkLinks(database.records));
	}

	@AfterEach
	void tearDown() {
		database.close();
	}

	private void metric(String scanType, long scanId) {
		database.jdbc.update("INSERT INTO rule_metric_scan(scan_type,scan_id,identity_key,rule_id,revision,module,bucket_start,findings,"
				+ "blocking,blocking_unknown,coverage,engine_status) VALUES (?,?,?,?,?,'test',?,3,0,0,'FULL','RAN')", scanType, scanId,
				"k" + scanType + scanId, RULE, REVISION, now);
	}

	private void repositoryScan(long scanId) {
		database.jdbc.update("INSERT INTO repo_scans(scan_id,plan_id,run_no,priority,submit_date,attempts,finding_count) VALUES (?,1,1,0,0,0,0)",
				scanId);
	}

	private List<String> urls() {
		return links.matchedReports(List.of(new RuleWorkLinks.RuleRef(RULE, "rule", REVISION)), 0).get(RULE).stream()
				.map(RuleWorkLinks.Link::url).toList();
	}

	@Test
	void aRepositoryScanThatWasDeletedGetsNoLink() {
		metric("repository", 13);

		assertThat(urls()).as("the scan 13 row is gone, so /reposcan/report/13 would be a 404").isEmpty();
	}

	@Test
	void aRepositoryScanThatStillExistsKeepsItsLink() {
		repositoryScan(14);
		metric("repository", 13);
		metric("repository", 14);

		assertThat(urls()).containsExactly("/reposcan/report/14?reviewSearch=rule");
	}

	@Test
	void aPullRequestScanThatWasDeletedGetsNoLinkAndOneThatExistsKeepsIt() {
		database.seedPr(7, 1);
		metric("pull_request", 7);
		metric("pull_request", 8);

		assertThat(urls()).containsExactly("/scan/report/7?reviewSearch=rule");
	}
}
