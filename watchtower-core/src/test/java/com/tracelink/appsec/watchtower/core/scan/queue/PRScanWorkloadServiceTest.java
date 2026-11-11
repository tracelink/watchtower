package com.tracelink.appsec.watchtower.core.scan.queue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.watchtower.core.scan.queue.PRScanWorkItemEntity.WorkStatus;

@ExtendWith(MockitoExtension.class)
class PRScanWorkloadServiceTest {
	@Mock PRScanWorkItemRepository repository;
	private PRScanWorkloadService service;

	@BeforeEach
	void setUp() {
		service = new PRScanWorkloadService(repository);
	}

	@Test
	void recordsQueuedRunningAndCompletedLifecycle() {
		ScanRequestMessage message = new ScanRequestMessage("Bitbucket", "payments", "42",
				"abc", System.currentTimeMillis() - 10_000);
		given(repository.findByDedupKey(PRScanWorkloadService.key(message)))
				.willReturn(Optional.empty());

		service.queued(message);

		verify(repository).save(org.mockito.ArgumentMatchers.argThat(item ->
				item.getStatus() == WorkStatus.QUEUED
				&& item.getRepoName().equals("payments") && item.getPrId().equals("42")));
		service.completed(message);
		verify(repository).deleteByDedupKey(PRScanWorkloadService.key(message));
	}

	@Test
	void onlyQueuedOrRunningWorkCountsAsAPendingScan() {
		// A scan that failed validation will never run, so a merge after it beat no scan
		given(repository.existsByApiLabelAndRepoNameAndPrIdAndStatusIn("Bitbucket", "payments",
				"42", java.util.List.of(WorkStatus.QUEUED, WorkStatus.RUNNING))).willReturn(true);

		org.junit.jupiter.api.Assertions.assertTrue(
				service.hasPendingScan("Bitbucket", "payments", "42"));
		org.junit.jupiter.api.Assertions.assertFalse(
				service.hasPendingScan("Bitbucket", "payments", "43"));
	}

	@Test
	void hashesLongLogicalKeysIntoFixedLengthDatabaseKeys() {
		ScanRequestMessage first = new ScanRequestMessage("Bitbucket", "r".repeat(500), "42",
				"a".repeat(200), 1L);
		ScanRequestMessage second = new ScanRequestMessage("Bitbucket", "r".repeat(500), "42",
				"b".repeat(200), 1L);

		assertEquals(64, PRScanWorkloadService.key(first).length());
		assertNotEquals(PRScanWorkloadService.key(first), PRScanWorkloadService.key(second));
	}

	@Test
	void summarizesQueuedAndRunningItemsWithOldestWait() {
		long now = System.currentTimeMillis();
		PRScanWorkItemEntity queued = item("repo-a", "1", WorkStatus.QUEUED,
				now - 125_000, null);
		PRScanWorkItemEntity running = item("repo-b", "2", WorkStatus.RUNNING,
				now - 60_000, now - 5_000);
		given(repository.findAllByStatusInOrderByEnqueuedAtAsc(
				List.of(WorkStatus.QUEUED, WorkStatus.RUNNING)))
				.willReturn(List.of(queued, running));
		given(repository.countByStatus(WorkStatus.QUEUED)).willReturn(1L);
		given(repository.countByStatus(WorkStatus.RUNNING)).willReturn(1L);

		PRScanWorkloadModel workload = service.getWorkload();

		assertEquals(1, workload.getQueued());
		assertEquals(1, workload.getRunning());
		assertEquals("2m", workload.getOldestWait());
		assertEquals(List.of("Queued", "Scanning"),
				workload.getItems().stream().map(PRScanWorkloadModel.Item::status).toList());
	}

	@Test
	void exposesRecentValidationFailuresWithoutCountingThemAsBacklog() {
		long now = System.currentTimeMillis();
		PRScanWorkItemEntity failed = item("repo-c", "3", WorkStatus.VALIDATION_FAILED,
				now - 30_000, null);
		failed.setFailureReason("Repository has no configured ruleset");
		given(repository.findAllByStatusAndUpdatedAtGreaterThanEqualOrderByEnqueuedAtAsc(
				org.mockito.ArgumentMatchers.eq(WorkStatus.VALIDATION_FAILED),
				org.mockito.ArgumentMatchers.anyLong())).willReturn(List.of(failed));
		given(repository.countByStatusAndUpdatedAtGreaterThanEqual(
				org.mockito.ArgumentMatchers.eq(WorkStatus.VALIDATION_FAILED),
				org.mockito.ArgumentMatchers.anyLong())).willReturn(1L);

		PRScanWorkloadModel workload = service.getWorkload();

		assertEquals(1, workload.getValidationFailed());
		assertEquals(0, workload.getQueued());
		assertEquals("Validation failed", workload.getItems().getFirst().status());
		assertEquals("Repository has no configured ruleset",
				workload.getItems().getFirst().reason());
	}

	@Test
	void dismissesARequestThatFailedValidation() {
		PRScanWorkItemEntity failed = item("repo-d", "4", WorkStatus.VALIDATION_FAILED,
				System.currentTimeMillis() - 30_000, null);
		given(repository.findById(5L)).willReturn(Optional.of(failed));

		service.dismissFailed(5L);

		verify(repository).delete(failed);
	}

	@Test
	void refusesToDismissARequestThatIsStillQueuedOrRunning() {
		PRScanWorkItemEntity queued = item("repo-e", "5", WorkStatus.QUEUED,
				System.currentTimeMillis() - 30_000, null);
		given(repository.findById(6L)).willReturn(Optional.of(queued));

		org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.dismissFailed(6L));

		verify(repository, org.mockito.Mockito.never()).delete(org.mockito.ArgumentMatchers.any());
	}

	@Test
	void refusesToDismissARequestThatNoLongerExists() {
		given(repository.findById(7L)).willReturn(Optional.empty());

		IllegalArgumentException refused = org.junit.jupiter.api.Assertions.assertThrows(
				IllegalArgumentException.class, () -> service.dismissFailed(7L));

		assertEquals("That request is no longer in the list", refused.getMessage());
	}

	@Test
	void onlyFailedItemsOfferDismissal() {
		long now = System.currentTimeMillis();
		PRScanWorkItemEntity failed = item("repo-f", "6", WorkStatus.VALIDATION_FAILED,
				now - 30_000, null);
		PRScanWorkItemEntity queued = item("repo-g", "7", WorkStatus.QUEUED, now - 20_000, null);

		org.junit.jupiter.api.Assertions
				.assertTrue(PRScanWorkloadModel.Item.from(failed, now).canDismiss());
		org.junit.jupiter.api.Assertions
				.assertFalse(PRScanWorkloadModel.Item.from(queued, now).canDismiss());
	}

	private PRScanWorkItemEntity item(String repo, String prId, WorkStatus status,
			long enqueuedAt, Long startedAt) {
		PRScanWorkItemEntity item = new PRScanWorkItemEntity();
		item.setDedupKey(repo + "/" + prId);
		item.setApiLabel("Bitbucket");
		item.setRepoName(repo);
		item.setPrId(prId);
		item.setStatus(status);
		item.setEnqueuedAt(enqueuedAt);
		item.setStartedAt(startedAt);
		return item;
	}

	@Test
	void aRequestQueuedForOverADayIsMovedToFailedSoItIsNotCountedAsWaiting() {
		PRScanWorkItemEntity old = new PRScanWorkItemEntity();
		old.setStatus(WorkStatus.QUEUED);
		old.setEnqueuedAt(System.currentTimeMillis() - java.time.Duration.ofDays(3).toMillis());
		given(repository.findAllByStatusAndEnqueuedAtLessThan(org.mockito.ArgumentMatchers.eq(WorkStatus.QUEUED),
				org.mockito.ArgumentMatchers.anyLong())).willReturn(List.of(old));

		service.getWorkload();

		assertEquals(WorkStatus.VALIDATION_FAILED, old.getStatus());
		org.junit.jupiter.api.Assertions.assertTrue(old.getFailureReason().contains("dropped"));
		verify(repository).saveAll(List.of(old));
	}
}
