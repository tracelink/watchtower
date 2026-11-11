package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.RepoWorkQueue;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

public class ExpandPlanHandlerTest {

	private static final long NOW = 100L * 86_400_000L;

	private RepoScanPlanRepository plans;

	private RepositoryRepository repositories;

	private RepoScanRepository scans;

	private RepoWorkQueue queue;

	private RepoScanPlanEntity plan;

	private ExpandPlanHandler handler;

	private final AsyncJobEntity job = new AsyncJobEntity();

	@BeforeEach
	public void setup() {
		plans = BDDMockito.mock(RepoScanPlanRepository.class);
		repositories = BDDMockito.mock(RepositoryRepository.class);
		scans = BDDMockito.mock(RepoScanRepository.class);
		queue = BDDMockito.mock(RepoWorkQueue.class);
		ApiIntegrationEntity integration = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integration.createApi()).thenReturn(BDDMockito.mock(IScmApi.class));
		ApiIntegrationService integrations = BDDMockito.mock(ApiIntegrationService.class);
		BDDMockito.when(integrations.findByLabel("bb")).thenReturn(integration);
		BDDMockito.when(scans.saveAll(ArgumentMatchers.anyList()))
				.thenAnswer(i -> i.getArgument(0));

		plan = new RepoScanPlanEntity();
		plan.setApiLabel("bb");
		plan.setFrequency(PlanFrequency.ONCE);
		plan.setRepoSelector("*");
		BDDMockito.when(plans.findById(4L)).thenReturn(Optional.of(plan));
		job.setPayload(ExpandPlanHandler.payload(4, 1));
		handler = new ExpandPlanHandler(plans, repositories, scans, integrations, queue, 2, 5,
				Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC));
	}

	private static RepositoryEntity repo(String name, int criticality, long lastCommit) {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRepoName(name);
		repo.setCriticality(criticality);
		repo.setDefaultBranch("main");
		repo.setLastCommitAt(lastCommit);
		return repo;
	}

	@SuppressWarnings("unchecked")
	private List<RepoScanEntity> savedRows() {
		ArgumentCaptor<List<RepoScanEntity>> rows = ArgumentCaptor.forClass(List.class);
		BDDMockito.verify(scans).saveAll(rows.capture());
		return rows.getValue();
	}

	@Test
	public void queuesMostCriticalRepositoriesFirstAndCapsTheRun() throws Exception {
		BDDMockito.when(repositories.findByScanTypeAndApiLabelAndEnabledTrue(
				CodeScanType.PULL_REQUEST, "bb")).thenReturn(List.of(repo("low", 4, NOW),
						repo("critical", 1, NOW), repo("normal", 3, NOW)));

		handler.handle(job, note -> {
		});

		List<RepoScanEntity> rows = savedRows();
		Assertions.assertEquals(List.of("critical", "normal"),
				rows.stream().map(r -> r.getRepository().getRepoName()).toList());
		Assertions.assertEquals(1, rows.get(0).getPriority());
		Assertions.assertEquals(ScanStatus.NOT_STARTED, rows.get(0).getStatus());
		Assertions.assertEquals("main", rows.get(0).getBranch());
		BDDMockito.verify(queue, BDDMockito.times(2)).sendScan(ArgumentMatchers.anyLong());
	}

	@Test
	public void theQueueSummaryIsSingularForOneScanInOneRepository() throws Exception {
		BDDMockito.when(repositories.findByScanTypeAndApiLabelAndEnabledTrue(
				CodeScanType.PULL_REQUEST, "bb")).thenReturn(List.of(repo("only", 3, NOW)));
		List<String> notes = new java.util.ArrayList<>();

		handler.handle(job, notes::add);

		Assertions.assertEquals(List.of("1 scan queued across 1 repository"), notes);
	}

	@Test
	public void theQueueSummaryIsPluralForSeveralScans() throws Exception {
		BDDMockito.when(repositories.findByScanTypeAndApiLabelAndEnabledTrue(
				CodeScanType.PULL_REQUEST, "bb")).thenReturn(List.of(repo("a", 3, NOW),
						repo("b", 3, NOW)));
		List<String> notes = new java.util.ArrayList<>();

		handler.handle(job, notes::add);

		Assertions.assertEquals(List.of("2 scans queued across 2 repositories"), notes);
	}

	@Test
	public void skipsPausedRepositories() throws Exception {
		RepositoryEntity paused = repo("paused", 1, NOW);
		paused.setScanningPaused(true);
		BDDMockito.when(repositories.findByScanTypeAndApiLabelAndEnabledTrue(
				CodeScanType.PULL_REQUEST, "bb")).thenReturn(List.of(paused,
						repo("running", 3, NOW)));

		handler.handle(job, note -> {
		});

		Assertions.assertEquals(List.of("running"), savedRows().stream()
				.map(r -> r.getRepository().getRepoName()).toList());
	}

	@Test
	public void skipsStaleRepositoriesWhenAsked() throws Exception {
		plan.setSkipStaleDays(30);
		BDDMockito.when(repositories.findByScanTypeAndApiLabelAndEnabledTrue(
				CodeScanType.PULL_REQUEST, "bb")).thenReturn(List.of(repo("fresh", 3, NOW),
						repo("stale", 3, NOW - 31L * 86_400_000L), repo("unknown", 3, 0)));

		handler.handle(job, note -> {
		});

		Assertions.assertEquals(List.of("fresh", "unknown"), savedRows().stream()
				.map(r -> r.getRepository().getRepoName()).toList());
	}

	@Test
	public void aRedeliveredRunRequeuesItsRowsInsteadOfDuplicating() throws Exception {
		RepoScanEntity waiting = new RepoScanEntity();
		waiting.setStatus(ScanStatus.NOT_STARTED);
		RepoScanEntity done = new RepoScanEntity();
		done.setStatus(ScanStatus.DONE);
		BDDMockito.when(scans.findRun(4, 1)).thenReturn(List.of(waiting, done));

		handler.handle(job, note -> {
		});

		BDDMockito.verify(scans, BDDMockito.never()).saveAll(ArgumentMatchers.anyList());
		BDDMockito.verify(queue, BDDMockito.times(1)).sendScan(ArgumentMatchers.anyLong());
	}
}
