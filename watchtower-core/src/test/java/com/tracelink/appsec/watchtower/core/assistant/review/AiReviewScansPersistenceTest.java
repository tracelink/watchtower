package com.tracelink.appsec.watchtower.core.assistant.review;

import static org.assertj.core.api.Assertions.assertThat;

import org.hibernate.Hibernate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/**
 * A resolved scan is read by the background job after the transaction that resolved it has closed, so its repository
 * must be loaded for real, not a lazy stand-in. Mocks cannot show this; the real mapping and session can.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
class AiReviewScansPersistenceTest {
	private static final String COMMIT = "d".repeat(40);

	@Autowired
	private AiReviewScans scans;
	@Autowired
	private RepositoryRepository repositories;
	@Autowired
	private RepoScanRepository repoScans;
	@Autowired
	private RepoScanPlanRepository plans;

	private long scanId;
	private long repositoryId;
	private long planId;

	@AfterEach
	void clean() {
		repoScans.deleteById(scanId);
		repositories.deleteById(repositoryId);
		plans.deleteById(planId);
	}

	@Test
	void aRepositoryScansRepositoryCanBeReadAfterTheTransactionThatResolvedItHasEnded() {
		var repo = new RepositoryEntity();
		repo.setApiLabel("bb");
		repo.setRepoName("ai-review-lazy-check");
		repo.setScanType(CodeScanType.PULL_REQUEST);
		repositoryId = repositories.save(repo).getId();
		var plan = new RepoScanPlanEntity();
		plan.setName("ai-review-lazy-check");
		plan.setApiLabel("bb");
		plan.setRepoSelector("*");
		plan.setFrequency(PlanFrequency.ONCE);
		plan.setCreatedBy("test");
		planId = plans.save(plan).getId();
		var scan = new RepoScanEntity();
		scan.setPlanId(planId);
		scan.setRunNo(1);
		scan.setRepository(repositories.findById(repositoryId).orElseThrow());
		scan.setBranch("main");
		scan.setCommitHash(COMMIT);
		scan.setStatus(ScanStatus.DONE);
		scanId = repoScans.save(scan).getId();

		var resolved = scans.resolve("repository", scanId);

		assertThat(Hibernate.isInitialized(resolved.repository())).isTrue();
		assertThat(resolved.repository().getRepoName()).isEqualTo("ai-review-lazy-check");
		assertThat(resolved.repository().getApiLabel()).isEqualTo("bb");
	}
}
