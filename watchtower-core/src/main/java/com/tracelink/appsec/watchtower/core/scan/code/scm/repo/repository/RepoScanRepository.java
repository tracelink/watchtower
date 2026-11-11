package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;

/**
 * Repository scan rows. The status changes a worker makes are conditional updates, so when
 * several pods hold the same queue message only one of them wins the scan.
 *
 * @author Watchtower
 */
@Repository
public interface RepoScanRepository extends JpaRepository<RepoScanEntity, Long> {
	@Query("SELECT s.id AS id, COALESCE(s.endDate, 0) AS endDate FROM RepoScanEntity s "
			+ "ORDER BY s.endDate DESC, s.id DESC")
	List<ResultKey> findResultKeys(Pageable page);

	@Query("SELECT s.id AS id, COALESCE(s.endDate, 0) AS endDate FROM RepoScanEntity s "
			+ "WHERE s.repository.id = :repositoryId ORDER BY s.endDate DESC, s.id DESC")
	List<ResultKey> findResultKeysForRepository(long repositoryId, Pageable page);

	interface ResultKey {
		long getId();
		long getEndDate();
	}

	/** Paging a many-to-one fetch is safe and keeps repository names available after the query. */
	@Query("SELECT s FROM RepoScanEntity s JOIN FETCH s.repository "
			+ "ORDER BY s.endDate DESC, s.id DESC")
	List<RepoScanEntity> findResultRows(Pageable page);

	@Query("SELECT s FROM RepoScanEntity s JOIN FETCH s.repository WHERE s.id IN :ids")
	List<RepoScanEntity> findResultRowsByIds(List<Long> ids);

	@Query("SELECT s FROM RepoScanEntity s JOIN FETCH s.repository "
			+ "WHERE s.repository.id = :repositoryId ORDER BY s.endDate DESC, s.id DESC")
	List<RepoScanEntity> findResultRowsForRepository(long repositoryId, Pageable page);

	long countByRepositoryId(long repositoryId);

	/**
	 * Claims a scan for a worker: one that has not started, or one whose worker stopped
	 * sending heartbeats (its pod died).
	 *
	 * @return 1 if this worker now owns the scan, 0 if another worker does or it is finished
	 */
	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("UPDATE RepoScanEntity s SET s.status = :running, s.workerId = :worker,"
			+ " s.heartbeatAt = :now, s.startDate = :now, s.attempts = s.attempts + 1"
			+ " WHERE s.id = :id AND (s.status = :notStarted"
			+ " OR (s.status = :running AND s.heartbeatAt < :staleBefore))")
	int claim(@Param("id") long id, @Param("worker") String worker, @Param("now") long now,
			@Param("staleBefore") long staleBefore,
			@Param("notStarted") ScanStatus notStarted, @Param("running") ScanStatus running);

	/**
	 * @return 1 if the worker still owns the running scan, 0 if it lost it
	 */
	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("UPDATE RepoScanEntity s SET s.heartbeatAt = :now"
			+ " WHERE s.id = :id AND s.workerId = :worker AND s.status = :running")
	int heartbeat(@Param("id") long id, @Param("worker") String worker, @Param("now") long now,
			@Param("running") ScanStatus running);

	@Query("SELECT s FROM RepoScanEntity s JOIN FETCH s.repository WHERE s.id = :id")
	Optional<RepoScanEntity> findWithRepository(@Param("id") long id);

	@Query("SELECT s FROM RepoScanEntity s JOIN FETCH s.repository"
			+ " WHERE s.planId = :planId AND s.runNo = :runNo ORDER BY s.priority, s.id")
	List<RepoScanEntity> findRun(@Param("planId") long planId, @Param("runNo") int runNo);

	/**
	 * @return the most recent finished scan of the branch other than {@code excludeId}, the
	 *         baseline for new and fixed findings and for skipping an unchanged branch
	 */
	Optional<RepoScanEntity> findFirstByRepositoryIdAndBranchAndStatusAndIdNotOrderByEndDateDesc(
			long repositoryId, String branch, ScanStatus status, long excludeId);

	long countByStatus(ScanStatus status);

	/**
	 * @return rows of (plan id, run number, status, count) for the given plans, for run
	 *         progress; uses the (plan_id, run_no) index
	 */
	@Query("SELECT s.planId, s.runNo, s.status, COUNT(s) FROM RepoScanEntity s"
			+ " WHERE s.planId IN :planIds GROUP BY s.planId, s.runNo, s.status")
	List<Object[]> countRunStatuses(@Param("planIds") List<Long> planIds);

	/**
	 * @return the scans of each given plan's latest run, in one query (the Runs list loads only
	 *         small runs this way; larger ones are summarized from their status counts)
	 */
	@Query("SELECT s FROM RepoScanEntity s WHERE s.planId IN :planIds AND s.runNo ="
			+ " (SELECT p.runCount FROM RepoScanPlanEntity p WHERE p.id = s.planId)")
	List<RepoScanEntity> findLatestRuns(@Param("planIds") List<Long> planIds);

	@Query("SELECT MIN(s.submitDate) FROM RepoScanEntity s WHERE s.status = :status")
	Long findOldestSubmitDate(@Param("status") ScanStatus status);

	/**
	 * @return scans in the given statuses, oldest first, with their repository (the queue
	 *         shows its name, and the session is closed by the time the page renders)
	 */
	@Query("SELECT s FROM RepoScanEntity s JOIN FETCH s.repository WHERE s.status IN :statuses"
			+ " ORDER BY s.submitDate, s.id")
	List<RepoScanEntity> findQueue(@Param("statuses") List<ScanStatus> statuses,
			Pageable page);

	/**
	 * @return the latest scans in one status, newest first, with their repository; one status
	 *         and submit order so the (status, submit_date) index serves it without a sort
	 */
	@Query("SELECT s FROM RepoScanEntity s JOIN FETCH s.repository WHERE s.status = :status"
			+ " ORDER BY s.submitDate DESC, s.id DESC")
	List<RepoScanEntity> findLatest(@Param("status") ScanStatus status, Pageable page);

	long countByStatusInAndSubmitDateBetween(List<ScanStatus> statuses, long start, long end);

	/**
	 * @return a repository's scans, newest first; the (repo_entity_id, branch, end_date) index
	 *         narrows to the repository's rows
	 */
	Page<RepoScanEntity> findByRepositoryIdOrderBySubmitDateDesc(long repositoryId,
			Pageable page);

	/**
	 * @return which of the repositories have a scan in one of the statuses (queued or running)
	 */
	@Query("SELECT DISTINCT s.repository.id FROM RepoScanEntity s"
			+ " WHERE s.repository.id IN :repoIds AND s.status IN :statuses")
	List<Long> findRepositoriesBeingScanned(@Param("repoIds") List<Long> repoIds,
			@Param("statuses") List<ScanStatus> statuses);

	/**
	 * Deletes every scan row of the repositories, before the repositories themselves (the
	 * foreign key restricts). Their reports in S3 expire under the bucket's lifecycle rule.
	 *
	 * @return how many scan rows were deleted
	 */
	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("DELETE FROM RepoScanEntity s WHERE s.repository.id IN :repoIds")
	int deleteByRepositoryIds(@Param("repoIds") List<Long> repoIds);

	@Query("SELECT s.id FROM RepoScanEntity s WHERE s.status IN :statuses"
			+ " ORDER BY s.priority, s.submitDate, s.id")
	List<Long> findIdsByStatusIn(@Param("statuses") List<ScanStatus> statuses);

	@Query("SELECT COUNT(DISTINCT s.repository.id) FROM RepoScanEntity s"
			+ " WHERE s.status = :done AND s.endDate >= :since")
	long countRepositoriesScannedSince(@Param("since") long since,
			@Param("done") ScanStatus done);
}
