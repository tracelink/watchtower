package com.tracelink.appsec.watchtower.core.scan.code;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/** Exercises the scalar projections and the repository-scoped history against real JPA. */
@SpringBootTest(classes = WatchtowerTestApplication.class)
class CodeScanResultRepositoriesTest {
	@Autowired private PRContainerRepository containers;
	@Autowired private PRScanRepository prs;
	@Autowired private RepositoryRepository repositories;
	@Autowired private RepoScanPlanRepository plans;
	@Autowired private RepoScanRepository repoScans;

	@Test
	@Transactional
	void resultKeysAndRowsResolveForBothScanTypes() {
		String name = "results-" + UUID.randomUUID();
		var repository = new RepositoryEntity();
		repository.setScanType(CodeScanType.REPOSITORY);
		repository.setApiLabel("bb");
		repository.setRepoName(name);
		repository = repositories.saveAndFlush(repository);

		var container = new PullRequestContainerEntity();
		container.setApiLabel("bb");
		container.setRepoName(name);
		container.setPrId("58");
		container.setAuthor("tester");
		container.setSourceBranch("feature");
		container.setDestinationBranch("main");
		container = containers.saveAndFlush(container);
		var pr = new PullRequestScanEntity();
		pr.setContainer(container);
		pr.setStatus(ScanStatus.DONE);
		pr.setSubmitDate(100);
		pr.setStartDate(110);
		pr.setEndDate(200);
		pr = prs.saveAndFlush(pr);
		long prId = pr.getId();

		var plan = new RepoScanPlanEntity();
		plan.setName(name);
		plan.setApiLabel("bb");
		plan.setRepoSelector(name);
		plan.setFrequency(PlanFrequency.ONCE);
		plan.setCreatedBy("tester");
		plan.setCreatedAt(100);
		plan = plans.saveAndFlush(plan);
		var repo = new RepoScanEntity();
		repo.setPlanId(plan.getId());
		repo.setRepository(repository);
		repo.setBranch("main");
		repo.setStatus(ScanStatus.DONE);
		repo.setSubmitDate(100);
		repo.setStartDate(120);
		repo.setEndDate(300);
		repo = repoScans.saveAndFlush(repo);
		long repoId = repo.getId();

		assertTrue(prs.findResultKeysForRepository("bb", Set.of(name), PageRequest.of(0, 20))
				.stream().anyMatch(key -> key.getId() == prId && key.getEndDate() == 200));
		assertTrue(repoScans.findResultKeysForRepository(repository.getId(), PageRequest.of(0, 20))
				.stream().anyMatch(key -> key.getId() == repoId && key.getEndDate() == 300));
		var prRow = prs.findResultRowsByIds(List.of(prId)).getFirst();
		assertEquals(name, prRow.getRepoName());
		assertEquals("58", prRow.getPrId());
		assertEquals(200, prRow.getEndDate());
		assertEquals(repoId, repoScans.findResultRowsByIds(List.of(repoId))
				.getFirst().getId());
	}
}
