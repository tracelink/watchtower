package com.tracelink.appsec.watchtower.core.job;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.BDDMockito;
import org.springframework.dao.DataIntegrityViolationException;

import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.RepoWorkQueue;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.WorkOutcome;

public class AsyncJobServiceTest {

	private AsyncJobRepository jobs;

	private RepoWorkQueue queue;

	private AsyncJobHandler handler;

	private AsyncJobService service;

	@BeforeEach
	public void setup() {
		jobs = BDDMockito.mock(AsyncJobRepository.class);
		queue = BDDMockito.mock(RepoWorkQueue.class);
		handler = BDDMockito.mock(AsyncJobHandler.class);
		BDDMockito.when(handler.type()).thenReturn(AsyncJobType.CATALOG_SYNC);
		BDDMockito.when(jobs.saveAndFlush(ArgumentMatchers.any()))
				.thenAnswer(i -> i.getArgument(0));
		BDDMockito.when(queue.sendJob(ArgumentMatchers.anyLong(), ArgumentMatchers.anyString()))
				.thenReturn(true);
		service = new AsyncJobService(jobs, queue, List.of(handler),
				Clock.fixed(Instant.ofEpochMilli(1_000_000), ZoneOffset.UTC));
	}

	private static AsyncJobEntity job(AsyncJobStatus status) {
		AsyncJobEntity job = new AsyncJobEntity();
		job.setType(AsyncJobType.CATALOG_SYNC);
		job.setStatus(status);
		job.setDedupKey("sync-bb label");
		return job;
	}

	@Test
	public void aJobThatStayedQueuedTooLongIsFailedSoItsDedupKeyIsFreed() {
		// Dev: a sync sat Queued for almost five days and every new sync was refused as "already running".
		BDDMockito.when(jobs.expireQueued(ArgumentMatchers.eq(List.of(AsyncJobType.CATALOG_SYNC)),
				ArgumentMatchers.eq(400_000L), ArgumentMatchers.eq(1_000_000L), ArgumentMatchers.anyString()))
				.thenReturn(1);

		Assertions.assertEquals(1, service.expireStalledQueued(List.of(AsyncJobType.CATALOG_SYNC), 600_000L));
		Assertions.assertEquals(0, service.expireStalledQueued(List.of(AsyncJobType.CATALOG_SYNC), 900_000L));
	}

	@Test
	public void aJobCountsAsInProgressOnlyWhileItIsRecent() {
		BDDMockito.when(jobs.existsByTypeAndStatusInAndCreatedAtGreaterThan(
				ArgumentMatchers.eq(AsyncJobType.CATALOG_SYNC), ArgumentMatchers.anyCollection(),
				ArgumentMatchers.eq(400_000L))).thenReturn(true);

		Assertions.assertTrue(service.hasActive(AsyncJobType.CATALOG_SYNC, 600_000L));
		Assertions.assertFalse(service.hasActive(AsyncJobType.CATALOG_SYNC, 100_000L));
	}

	@Test
	public void enqueueSendsToTheDedupGroupAndRefusesADuplicate() {
		Assertions.assertTrue(service.enqueue(AsyncJobType.CATALOG_SYNC, "{}", "sync-bb label",
				"me").isPresent());
		BDDMockito.verify(queue).sendJob(0L, "job-sync-bb_label");

		BDDMockito.when(jobs.saveAndFlush(ArgumentMatchers.any()))
				.thenThrow(new DataIntegrityViolationException("dup"));
		Assertions.assertTrue(service.enqueue(AsyncJobType.CATALOG_SYNC, "{}", "sync-bb label",
				"me").isEmpty());
	}

	@Test
	public void enqueueMarksTheJobFailedWhenTheQueueRefusesIt() {
		BDDMockito.when(queue.sendJob(ArgumentMatchers.anyLong(), ArgumentMatchers.anyString()))
				.thenReturn(false);
		Assertions.assertTrue(service.enqueue(AsyncJobType.CATALOG_SYNC, "{}", null, "me")
				.isEmpty());
		BDDMockito.verify(jobs).finish(0L, AsyncJobStatus.FAILED, 1_000_000,
				"Could not queue the job", null);
	}

	@Test
	public void runRecordsDoneRetryAndFailure() throws Exception {
		BDDMockito.when(jobs.claim(ArgumentMatchers.eq(5L), ArgumentMatchers.anyLong(),
				ArgumentMatchers.anyLong(), ArgumentMatchers.any(), ArgumentMatchers.any()))
				.thenReturn(1);
		AsyncJobEntity running = job(AsyncJobStatus.RUNNING);
		BDDMockito.when(jobs.findById(5L)).thenReturn(Optional.of(running));

		BDDMockito.when(handler.handle(ArgumentMatchers.any(), ArgumentMatchers.any()))
				.thenReturn("exports/5.csv");
		Assertions.assertFalse(service.run(5).retry());
		BDDMockito.verify(jobs).finish(5L, AsyncJobStatus.DONE, 1_000_000, null,
				"exports/5.csv");

		BDDMockito.willThrow(new RetryLaterException("rate limited", 90)).given(handler)
				.handle(ArgumentMatchers.any(), ArgumentMatchers.any());
		WorkOutcome retry = service.run(5);
		Assertions.assertTrue(retry.retry());
		Assertions.assertEquals(90, retry.delaySeconds());
		Assertions.assertEquals(AsyncJobStatus.QUEUED, running.getStatus());

		BDDMockito.willThrow(new IllegalStateException("Integration bb no longer exists"))
				.given(handler).handle(ArgumentMatchers.any(), ArgumentMatchers.any());
		Assertions.assertFalse(service.run(5).retry());
		BDDMockito.verify(jobs).finish(5L, AsyncJobStatus.FAILED, 1_000_000,
				"Integration bb no longer exists", null);
	}

	@Test
	public void aJobClaimedElsewhereIsRetriedAndAFinishedOneDropped() {
		BDDMockito.when(jobs.findById(6L)).thenReturn(Optional.of(job(AsyncJobStatus.RUNNING)));
		Assertions.assertTrue(service.run(6).retry());
		BDDMockito.when(jobs.findById(6L)).thenReturn(Optional.of(job(AsyncJobStatus.DONE)));
		Assertions.assertFalse(service.run(6).retry());
	}

	@Test
	public void aJobWithoutAHandlerFails() {
		BDDMockito.when(jobs.claim(ArgumentMatchers.eq(7L), ArgumentMatchers.anyLong(),
				ArgumentMatchers.anyLong(), ArgumentMatchers.any(), ArgumentMatchers.any()))
				.thenReturn(1);
		AsyncJobEntity export = job(AsyncJobStatus.RUNNING);
		export.setType(AsyncJobType.EXPORT_RUN);
		BDDMockito.when(jobs.findById(7L)).thenReturn(Optional.of(export));

		Assertions.assertFalse(service.run(7).retry());
		BDDMockito.verify(jobs).finish(7L, AsyncJobStatus.FAILED, 1_000_000,
				"No handler for this job type", null);
	}
}
