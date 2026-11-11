package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobRepository;
import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/**
 * Runs the repository scan queries against the real Flyway schema (V056).
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
public class RepoScanPersistenceTest {

	@Autowired
	private RepositoryRepository repositories;

	@Autowired
	private RepoScanPlanRepository plans;

	@Autowired
	private RepoScanRepository scans;

	@Autowired
	private RepoScanSettingsRepository settings;

	@Autowired
	private AsyncJobRepository jobs;

	private RepositoryEntity repo;

	private RepoScanPlanEntity plan;

	@BeforeEach
	public void seed() {
		scans.deleteAll();
		plans.deleteAll();
		jobs.deleteAll();
		repositories.deleteAll();
		repo = new RepositoryEntity();
		repo.setApiLabel("bb");
		repo.setRepoName("payments-api");
		repo.setScanType(CodeScanType.PULL_REQUEST);
		repo.setEnabled(true);
		repo = repositories.saveAndFlush(repo);

		plan = new RepoScanPlanEntity();
		plan.setName("adhoc");
		plan.setApiLabel("bb");
		plan.setRepoSelector("payments-api");
		plan.setFrequency(PlanFrequency.ONCE);
		plan.setCreatedBy("tester");
		plan.setCreatedAt(1);
		plan = plans.saveAndFlush(plan);
	}

	private RepoScanEntity newScan(ScanStatus status, long endDate) {
		RepoScanEntity scan = new RepoScanEntity();
		scan.setPlanId(plan.getId());
		scan.setRunNo(1);
		scan.setRepository(repo);
		scan.setBranch("main");
		scan.setStatus(status);
		scan.setSubmitDate(1);
		if (endDate > 0) {
			scan.setEndDate(endDate);
		}
		return scans.saveAndFlush(scan);
	}

	@Test
	public void onlyOneWorkerClaimsAScanUntilItsHeartbeatGoesStale() {
		long id = newScan(ScanStatus.NOT_STARTED, 0).getId();

		Assertions.assertEquals(1, scans.claim(id, "pod-a", 1_000, 0, ScanStatus.NOT_STARTED,
				ScanStatus.IN_PROGRESS));
		Assertions.assertEquals(0, scans.claim(id, "pod-b", 1_500, 500, ScanStatus.NOT_STARTED,
				ScanStatus.IN_PROGRESS));
		Assertions.assertEquals(1, scans.heartbeat(id, "pod-a", 2_000, ScanStatus.IN_PROGRESS));
		Assertions.assertEquals(0, scans.heartbeat(id, "pod-b", 2_000, ScanStatus.IN_PROGRESS));

		// pod-a stops sending heartbeats: anything older than 3_000 counts as dead
		Assertions.assertEquals(1, scans.claim(id, "pod-b", 9_000, 3_000, ScanStatus.NOT_STARTED,
				ScanStatus.IN_PROGRESS));
		RepoScanEntity claimed = scans.findById(id).orElseThrow();
		Assertions.assertEquals("pod-b", claimed.getWorkerId());
		Assertions.assertEquals(2, claimed.getAttempts());
		Assertions.assertEquals(ScanStatus.IN_PROGRESS, claimed.getStatus());
	}

	@Test
	public void findsTheLatestFinishedScanOfTheBranchAndTheRun() {
		RepoScanEntity older = newScan(ScanStatus.DONE, 100);
		RepoScanEntity newer = newScan(ScanStatus.DONE, 200);
		RepoScanEntity current = newScan(ScanStatus.IN_PROGRESS, 0);

		RepoScanEntity previous = scans
				.findFirstByRepositoryIdAndBranchAndStatusAndIdNotOrderByEndDateDesc(repo.getId(),
						"main", ScanStatus.DONE, current.getId())
				.orElseThrow();

		Assertions.assertEquals(newer.getId(), previous.getId());
		Assertions.assertNotEquals(older.getId(), previous.getId());
		Assertions.assertEquals(3, scans.findRun(plan.getId(), 1).size());
		Assertions.assertEquals(1, scans.countRepositoriesScannedSince(150, ScanStatus.DONE));
	}

	@Test
	public void repositoryNamesAreUniquePerIntegration() {
		RepositoryEntity duplicate = new RepositoryEntity();
		duplicate.setApiLabel("bb");
		duplicate.setRepoName("payments-api");
		duplicate.setScanType(CodeScanType.PULL_REQUEST);

		Assertions.assertThrows(DataIntegrityViolationException.class,
				() -> repositories.saveAndFlush(duplicate));
	}

	@Test
	public void planRunIsClaimedOnce() {
		plan.setFrequency(PlanFrequency.DAILY);
		plan.setNextRunAt(100L);
		plans.saveAndFlush(plan);

		Assertions.assertEquals(1, plans.findDue(150, PlanFrequency.ONCE).size());
		Assertions.assertEquals(1, plans.claimRun(plan.getId(), 100, 0, 900, 150));
		Assertions.assertEquals(0, plans.claimRun(plan.getId(), 100, 0, 900, 150));
		Assertions.assertEquals(1, plans.findById(plan.getId()).orElseThrow().getRunCount());
		Assertions.assertTrue(plans.findDue(150, PlanFrequency.ONCE).isEmpty());
	}

	@Test
	public void twoStartsSeeingOneRunCountNeverShareARunNumber() {
		plans.saveAndFlush(plan);
		// Two "Run now" presses (or pods) both read run count 0: only one takes run 1
		Assertions.assertEquals(1, plans.startRun(plan.getId(), 0, 150));
		Assertions.assertEquals(0, plans.startRun(plan.getId(), 0, 151));
		Assertions.assertEquals(1, plans.startRun(plan.getId(), 1, 152));
		Assertions.assertEquals(2, plans.findById(plan.getId()).orElseThrow().getRunCount());
	}

	@Test
	public void aScheduledRunDoesNotTakeANumberRunNowTookMeanwhile() {
		plan.setFrequency(PlanFrequency.DAILY);
		plan.setNextRunAt(100L);
		plans.saveAndFlush(plan);
		// The trigger read run count 0, then "Run now" took run 1
		Assertions.assertEquals(1, plans.startRun(plan.getId(), 0, 120));
		Assertions.assertEquals(0, plans.claimRun(plan.getId(), 100, 0, 900, 150),
				"the scheduled run waits for the next check instead of reusing run 1");
		Assertions.assertEquals(1, plans.claimRun(plan.getId(), 100, 1, 900, 160));
		Assertions.assertEquals(2, plans.findById(plan.getId()).orElseThrow().getRunCount());
	}

	@Test
	public void jobDedupKeyBlocksADuplicateUntilTheFirstFinishes() {
		AsyncJobEntity first = jobs.saveAndFlush(job("sync-bb"));
		Assertions.assertThrows(DataIntegrityViolationException.class,
				() -> jobs.saveAndFlush(job("sync-bb")));

		Assertions.assertEquals(1, jobs.claim(first.getId(), 10, 0, AsyncJobStatus.QUEUED,
				AsyncJobStatus.RUNNING));
		Assertions.assertEquals(0, jobs.claim(first.getId(), 11, 5, AsyncJobStatus.QUEUED,
				AsyncJobStatus.RUNNING));
		jobs.finish(first.getId(), AsyncJobStatus.DONE, 20, null, null);

		Assertions.assertNotNull(jobs.saveAndFlush(job("sync-bb")));
		Assertions.assertEquals(1, jobs.deleteFinishedBefore(30));
		Assertions.assertEquals(1, jobs.findTop50ByStatusInOrderByCreatedAtAsc(
				List.of(AsyncJobStatus.QUEUED, AsyncJobStatus.RUNNING)).size());
	}

	@Test
	public void settingsRowExistsFromTheMigration() {
		RepoScanSettingsEntity row = settings.findById(RepoScanSettingsEntity.SINGLETON_ID)
				.orElseThrow();
		Assertions.assertFalse(row.isPaused());
		Assertions.assertEquals(6, row.getSyncFrequencyHours());
	}

	@Test
	public void aSyncThatNeverStartedIsFailedAndItsKeyFreedWhileARecentOneIsLeftAlone() {
		// Dev: a sync sat Queued for almost five days, so every new sync was refused as "already running".
		AsyncJobEntity old = job("sync-old");
		old.setCreatedAt(1_000);
		AsyncJobEntity recent = job("sync-recent");
		recent.setCreatedAt(900_000);
		old = jobs.saveAndFlush(old);
		recent = jobs.saveAndFlush(recent);

		int expired = jobs.expireQueued(java.util.List.of(AsyncJobType.CATALOG_SYNC), 500_000, 1_000_000,
				"Waited too long");

		Assertions.assertEquals(1, expired);
		AsyncJobEntity failed = jobs.findById(old.getId()).orElseThrow();
		Assertions.assertEquals(AsyncJobStatus.FAILED, failed.getStatus());
		Assertions.assertNull(failed.getDedupKey(), "the dedup key is free for a new request");
		Assertions.assertEquals(AsyncJobStatus.QUEUED, jobs.findById(recent.getId()).orElseThrow().getStatus());
		Assertions.assertTrue(jobs.saveAndFlush(job("sync-old")).getId() > 0, "the same work can be queued again");
		Assertions.assertTrue(jobs.existsByTypeAndStatusInAndCreatedAtGreaterThan(AsyncJobType.CATALOG_SYNC,
				java.util.List.of(AsyncJobStatus.QUEUED), 500_000));
		Assertions.assertFalse(jobs.existsByTypeAndStatusInAndCreatedAtGreaterThan(AsyncJobType.CATALOG_SYNC,
				java.util.List.of(AsyncJobStatus.RUNNING), 500_000));
	}

	private static AsyncJobEntity job(String dedupKey) {
		AsyncJobEntity job = new AsyncJobEntity();
		job.setType(AsyncJobType.CATALOG_SYNC);
		job.setStatus(AsyncJobStatus.QUEUED);
		job.setDedupKey(dedupKey);
		job.setCreatedAt(1);
		return job;
	}
}
