package com.tracelink.appsec.watchtower.core.scan.queue;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tracelink.appsec.watchtower.core.scan.queue.PRScanWorkItemEntity.WorkStatus;

public interface PRScanWorkItemRepository extends JpaRepository<PRScanWorkItemEntity, Long> {
	Optional<PRScanWorkItemEntity> findByDedupKey(String dedupKey);
	List<PRScanWorkItemEntity> findAllByOrderByEnqueuedAtAsc();
	List<PRScanWorkItemEntity> findAllByStatusInOrderByEnqueuedAtAsc(List<WorkStatus> statuses);
	List<PRScanWorkItemEntity> findAllByStatusAndUpdatedAtGreaterThanEqualOrderByEnqueuedAtAsc(
			WorkStatus status, long updatedAt);
	List<PRScanWorkItemEntity> findAllByStatusAndEnqueuedAtLessThan(WorkStatus status, long enqueuedAt);
	long countByStatus(WorkStatus status);
	boolean existsByApiLabelAndRepoNameAndPrIdAndStatusIn(String apiLabel, String repoName,
			String prId, Collection<WorkStatus> statuses);
	long countByStatusAndUpdatedAtGreaterThanEqual(WorkStatus status, long updatedAt);
	void deleteByDedupKey(String dedupKey);
}
