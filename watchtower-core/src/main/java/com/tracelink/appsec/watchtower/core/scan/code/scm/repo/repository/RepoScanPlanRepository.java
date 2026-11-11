package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;

/**
 * Repository scan plans.
 *
 * @author Watchtower
 */
@Repository
public interface RepoScanPlanRepository extends JpaRepository<RepoScanPlanEntity, Long> {

	@Query("SELECT p FROM RepoScanPlanEntity p WHERE p.enabled = true AND p.frequency <> :once"
			+ " AND p.nextRunAt <= :now ORDER BY p.nextRunAt")
	List<RepoScanPlanEntity> findDue(@Param("now") long now,
			@Param("once") PlanFrequency once);

	/**
	 * Takes the next run of a due plan. Only the pod whose update sees the old next-run time and
	 * run count starts the run, so two pods never start the same run, and the run is numbered
	 * {@code runCount + 1} exactly, even if "Run now" was pressed meanwhile (then nothing
	 * changes, and the next check takes it).
	 *
	 * @return 1 if this caller starts the run, 0 if another already did
	 */
	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("UPDATE RepoScanPlanEntity p SET p.nextRunAt = :next, p.lastRunAt = :now,"
			+ " p.runCount = p.runCount + 1 WHERE p.id = :id AND p.nextRunAt = :expected"
			+ " AND p.runCount = :runCount")
	int claimRun(@Param("id") long id, @Param("expected") long expected,
			@Param("runCount") int runCount, @Param("next") long next, @Param("now") long now);

	/**
	 * Numbers a run started by hand: only if the run count is still {@code runCount}, so two
	 * presses (or pods) at once never give two runs one number.
	 *
	 * @return 1 if this caller took run {@code runCount + 1}, 0 if another took it first
	 */
	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("UPDATE RepoScanPlanEntity p SET p.runCount = p.runCount + 1, p.lastRunAt = :now"
			+ " WHERE p.id = :id AND p.runCount = :runCount")
	int startRun(@Param("id") long id, @Param("runCount") int runCount, @Param("now") long now);

	Page<RepoScanPlanEntity> findByFrequencyNot(PlanFrequency frequency, Pageable pageable);

	Page<RepoScanPlanEntity> findByRunCountGreaterThan(int runCount, Pageable pageable);

	long countByFrequencyNot(PlanFrequency frequency);

	long countByRunCountGreaterThan(int runCount);
}
