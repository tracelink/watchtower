package com.tracelink.appsec.watchtower.core.scan.code.scm.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

class QueueJobViewTest {

	private static AsyncJobEntity job(AsyncJobType type, AsyncJobStatus status, String progress,
			String error) {
		AsyncJobEntity job = new AsyncJobEntity();
		job.setType(type);
		job.setStatus(status);
		job.setProgress(progress);
		job.setError(error);
		job.setCreatedAt(1_760_000_000_000L);
		return job;
	}

	@Test
	void anIntegrationCheckWithAFailureIsAmberAndNamesIt() {
		QueueJobView view = QueueJobView.of(job(AsyncJobType.INTEGRATION_HEALTH, AsyncJobStatus.DONE,
				"2 checked, 1 failing: Example (Amazon ECR)", null));

		assertEquals("Integration check", view.title());
		assertEquals("verified", view.icon());
		assertEquals("1 of 2 failing", view.result());
		assertEquals("warning", view.tone());
		assertEquals("warning", view.resultIcon());
		assertTrue(view.resultTip().startsWith("Example (Amazon ECR) failed its check."));
		assertTrue(view.resultTip().endsWith("Click to open Integrations."));
		assertEquals("/apisettings", view.link());
		assertEquals(List.of("2 checked"), view.chips());
	}

	@Test
	void onlyAFailedOrPartlyFailedQueueJobCanBeDiagnosed() {
		AsyncJobEntity failingCheck = job(AsyncJobType.INTEGRATION_HEALTH, AsyncJobStatus.DONE,
				"2 checked, 1 failing: Example (Amazon ECR)", null);
		QueueJobView partly = QueueJobView.of(failingCheck);
		assertTrue(partly.diagnosable(), "an integration check with a failure");
		AsyncJobEntity failed = job(AsyncJobType.EXPAND_PLAN, AsyncJobStatus.FAILED, "", "Plan timed out");
		assertTrue(QueueJobView.of(failed).diagnosable());
		assertEquals(false, QueueJobView.of(job(AsyncJobType.CATALOG_SYNC, AsyncJobStatus.DONE,
				"1 repositories, 0 changed, 0 gone", null)).diagnosable(), "a job that worked has nothing to diagnose");
		assertEquals(false, QueueJobView.of(job(AsyncJobType.RULE_CANDIDATE_TEST, AsyncJobStatus.FAILED, "", "boom")).diagnosable(),
				"admin and evaluation jobs are not on this page's list");
		assertEquals(false, QueueJobView.of(job(AsyncJobType.AI_BATCH_TRIAGE, AsyncJobStatus.FAILED, "", "boom")).diagnosable());
		assertEquals("fact_check", QueueJobView.of(job(AsyncJobType.AI_BATCH_TRIAGE, AsyncJobStatus.DONE, "DONE 3/3", null)).icon());
	}

	@Test
	void anOlderCheckWithoutNamesStillSaysHowManyFailed() {
		QueueJobView view = QueueJobView.of(job(AsyncJobType.INTEGRATION_HEALTH, AsyncJobStatus.DONE,
				"2 checked, 1 failing", null));

		assertEquals("1 of 2 failing", view.result());
		assertEquals("1 integration failed its check. Click to open Integrations.", view.resultTip());
	}

	@Test
	void aCleanCheckIsGreen() {
		QueueJobView view = QueueJobView.of(job(AsyncJobType.INTEGRATION_HEALTH, AsyncJobStatus.DONE,
				"2 checked, 0 failing", null));

		assertEquals("Done", view.result());
		assertEquals("success", view.tone());
		assertEquals("All 2 integrations connected.", view.resultTip());
		assertNull(view.link());
	}

	@Test
	void aRepositorySyncReadsAsChipsWithTheRightPlural() {
		QueueJobView one = QueueJobView.of(job(AsyncJobType.CATALOG_SYNC, AsyncJobStatus.DONE,
				"1 repositories, 0 changed, 0 gone", null));
		QueueJobView many = QueueJobView.of(job(AsyncJobType.CATALOG_SYNC, AsyncJobStatus.DONE,
				"448 repositories, 3 changed, 1 gone", null));

		assertEquals("sync", one.icon());
		assertEquals(List.of("1 repository", "0 changed", "0 gone"), one.chips());
		assertEquals(List.of("448 repositories", "3 changed", "1 gone"), many.chips());
		assertEquals("Done", one.result());
		assertEquals("Finished without errors.", one.resultTip());
	}

	@Test
	void aFailedJobShowsItsErrorOnHover() {
		QueueJobView view = QueueJobView.of(job(AsyncJobType.CATALOG_SYNC, AsyncJobStatus.FAILED,
				"12 repositories listed", "Bitbucket said no"));

		assertEquals("Failed", view.result());
		assertEquals("danger", view.tone());
		assertEquals("Bitbucket said no", view.resultTip());
		assertEquals(List.of("12 repositories listed"), view.chips());
	}

	@Test
	void otherJobsKeepTheirProgressAsOneChip() {
		QueueJobView view = QueueJobView.of(job(AsyncJobType.EXPAND_PLAN, AsyncJobStatus.RUNNING,
				"40 repositories queued", null));

		assertEquals("Prepare scan run", view.title());
		assertEquals("playlist_add", view.icon());
		assertEquals("Running", view.result());
		assertEquals("info", view.tone());
		assertEquals(List.of("40 repositories queued"), view.chips());
		assertEquals(1_760_000_000_000L, view.createdAt());
	}

	@Test
	void filtersNameTheirJobTypes() {
		assertEquals(List.of(AsyncJobType.INTEGRATION_HEALTH), QueueJobView.Filter.of("checks").types());
		assertEquals(List.of(AsyncJobType.CATALOG_SYNC), QueueJobView.Filter.of("syncs").types());
		assertEquals(List.of(AsyncJobType.EXPAND_PLAN, AsyncJobType.EXPORT_RUN),
				QueueJobView.Filter.of("runs").types());
		assertEquals(QueueJobView.Filter.ALL, QueueJobView.Filter.of("bogus"));
		assertEquals(QueueJobView.Filter.ALL, QueueJobView.Filter.of(null));
	}
}
