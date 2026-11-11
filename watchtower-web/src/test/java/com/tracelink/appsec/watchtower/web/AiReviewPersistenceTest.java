package com.tracelink.appsec.watchtower.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.assistant.review.AiReviewFileEntity;
import com.tracelink.appsec.watchtower.core.assistant.review.AiReviewFileRepository;
import com.tracelink.appsec.watchtower.core.assistant.review.AiReviewItemEntity;
import com.tracelink.appsec.watchtower.core.assistant.review.AiReviewItemRepository;
import com.tracelink.appsec.watchtower.core.assistant.review.AiReviewRunEntity;
import com.tracelink.appsec.watchtower.core.assistant.review.AiReviewRunRepository;
import com.tracelink.appsec.watchtower.core.assistant.review.AiReviewScans;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;

/** The AI review's tables and the query for a pull request's findings, against the real mapping and database. */
@SpringBootTest(properties = {"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
		"spring.datasource.url=jdbc:h2:mem:ai-review;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@ActiveProfiles("dev")
@Transactional
class AiReviewPersistenceTest {
	@MockitoBean
	com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
	@Autowired
	AiReviewRunRepository runs;
	@Autowired
	AiReviewFileRepository files;
	@Autowired
	AiReviewItemRepository items;
	@Autowired
	AiReviewScans scans;

	@Test
	void theQueryForAPullRequestsFindingsRunsAndAnEmptyScanHasNoneAndIsComplete() {
		var scan = new AiReviewScans.Scan("pull_request", 987654321L, null, "c".repeat(40), new PullRequest("Bitbucket"));

		var points = scans.findings(scan);

		assertThat(points.points()).isEmpty();
		assertThat(points.complete()).isTrue();
	}

	@Test
	void runsFilesAndPointsAreStoredFoundAndRemovedTogether() {
		runs.saveAndFlush(new AiReviewRunEntity("run-old", "pull_request", 7, "alice", 1, 1_000L, 2_000L));
		runs.saveAndFlush(new AiReviewRunEntity("run-new", "pull_request", 7, "alice", 2, 5_000L, 9_000L));
		runs.saveAndFlush(new AiReviewRunEntity("run-other", "repository", 7, "bob", 1, 6_000L, 9_000L));
		files.saveAndFlush(new AiReviewFileEntity("f1", "run-old", "src/B.java"));
		files.saveAndFlush(new AiReviewFileEntity("f2", "run-old", "src/A.java"));
		items.saveAndFlush(new AiReviewItemEntity("i2", "run-old", "src/A.java", 20, 21, "CWE-89", "later", "high", "pmd", "GAP", null, 1_000L));
		items.saveAndFlush(new AiReviewItemEntity("i1", "run-old", "src/A.java", 10, 11, "CWE-79", "earlier", "low", null, "COVERED", "SomeRule", 1_000L));

		assertThat(runs.findTop5ByScanTypeAndScanIdOrderByCreatedAtDesc("pull_request", 7)).extracting(AiReviewRunEntity::getRunId).containsExactly("run-new", "run-old");
		assertThat(runs.countByRequestedByAndStatusIn("alice", Set.of("QUEUED", "RUNNING"))).isEqualTo(2);
		assertThat(runs.countByRequestedByAndStatusIn("alice", Set.of("DONE"))).isZero();
		assertThat(files.findByRunIdOrderByPath("run-old")).extracting(AiReviewFileEntity::getPath).containsExactly("src/A.java", "src/B.java");
		assertThat(items.findByRunIdOrderByPathAscFirstLineAsc("run-old")).extracting(AiReviewItemEntity::getFirstLine).containsExactly(10, 20);

		assertThat(runs.findByExpiresAtLessThan(3_000L)).extracting(AiReviewRunEntity::getRunId).containsExactly("run-old");
		List<String> expired = List.of("run-old");
		items.deleteByRunIdIn(expired);
		files.deleteByRunIdIn(expired);
		runs.deleteAll(runs.findByExpiresAtLessThan(3_000L));
		runs.flush();

		assertThat(items.findByRunIdOrderByPathAscFirstLineAsc("run-old")).isEmpty();
		assertThat(files.findByRunIdOrderByPath("run-old")).isEmpty();
		assertThat(runs.findById("run-old")).isEmpty();
		assertThat(runs.findById("run-new")).isPresent();
	}

	@Test
	void aRunKeepsTheFocusItWasStartedWithAndNoneIsNone() {
		var withFocus = new AiReviewRunEntity("run-focus", "repository", 12, "alice", 3, 1_000L, 2_000L);
		withFocus.setFocus("input validation and logging");
		runs.saveAndFlush(withFocus);
		runs.saveAndFlush(new AiReviewRunEntity("run-plain", "repository", 12, "alice", 3, 1_000L, 2_000L));

		assertThat(runs.findById("run-focus").orElseThrow().getFocus()).isEqualTo("input validation and logging");
		assertThat(runs.findById("run-plain").orElseThrow().getFocus()).isNull();
	}

	@Test
	void aPointRemembersWhoDecidedIt() {
		var item = new AiReviewItemEntity("i9", "run-x", "src/A.java", 1, 2, "CWE-22", "path from input", "medium", null, "GAP", null, 1_000L);
		assertThat(item.getState()).isEqualTo("OPEN");

		item.decide("CONFIRMED", "alice", 2_000L);
		items.saveAndFlush(item);

		var saved = items.findById("i9").orElseThrow();
		assertThat(saved.getState()).isEqualTo("CONFIRMED");
		assertThat(saved.getDecidedBy()).isEqualTo("alice");
		assertThat(saved.getDecidedAt()).isEqualTo(2_000L);
	}
}
