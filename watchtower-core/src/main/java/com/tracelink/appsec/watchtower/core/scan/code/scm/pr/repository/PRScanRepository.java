package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestMCRStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IScanRepository;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * Scan Repository for Pull Requests
 *
 * @author csmith
 *
 */
@Repository("prScanRepository")
public interface PRScanRepository extends IScanRepository<PullRequestScanEntity> {
	@Query("SELECT s.id AS id, s.endDate AS endDate FROM PullRequestScanEntity s "
			+ "ORDER BY s.endDate DESC, s.id DESC")
	List<ResultKey> findResultKeys(Pageable page);

	@Query("SELECT s.id AS id, s.endDate AS endDate FROM PullRequestScanEntity s "
			+ "JOIN s.container c WHERE c.apiLabel = :apiLabel AND c.repoName IN :repoNames "
			+ "ORDER BY s.endDate DESC, s.id DESC")
	List<ResultKey> findResultKeysForRepository(String apiLabel, Set<String> repoNames,
			Pageable page);

	interface ResultKey {
		long getId();
		long getEndDate();
	}

	/** Scalar rows avoid the entity's eager scan/finding collections on combined results pages. */
	@Query("SELECT s.id AS id, s.status AS status, s.submitDate AS submitDate, "
			+ "s.startDate AS startDate, s.endDate AS endDate, "
			+ "s.scannerExecutionsJson AS scannerExecutionsJson, "
			+ "s.scannerTimingsJson AS scannerTimingsJson, "
			+ "s.providerSummaryJson AS providerSummaryJson, "
			+ "c.repoName AS repoName, c.prId AS prId, c.apiLabel AS apiLabel, "
			+ "c.resolved AS resolved FROM PullRequestScanEntity s JOIN s.container c "
			+ "ORDER BY s.endDate DESC, s.id DESC")
	List<ResultRow> findResultRows(Pageable page);

	@Query("SELECT s.id AS id, s.status AS status, s.submitDate AS submitDate, "
			+ "s.startDate AS startDate, s.endDate AS endDate, "
			+ "s.scannerExecutionsJson AS scannerExecutionsJson, "
			+ "s.scannerTimingsJson AS scannerTimingsJson, "
			+ "s.providerSummaryJson AS providerSummaryJson, "
			+ "c.repoName AS repoName, c.prId AS prId, c.apiLabel AS apiLabel, "
			+ "c.resolved AS resolved FROM PullRequestScanEntity s JOIN s.container c "
			+ "WHERE s.id IN :ids")
	List<ResultRow> findResultRowsByIds(List<Long> ids);

	@Query("SELECT s.id AS id, s.status AS status, s.submitDate AS submitDate, "
			+ "s.startDate AS startDate, s.endDate AS endDate, "
			+ "s.scannerExecutionsJson AS scannerExecutionsJson, "
			+ "s.scannerTimingsJson AS scannerTimingsJson, "
			+ "s.providerSummaryJson AS providerSummaryJson, "
			+ "c.repoName AS repoName, c.prId AS prId, c.apiLabel AS apiLabel, "
			+ "c.resolved AS resolved FROM PullRequestScanEntity s JOIN s.container c "
			+ "WHERE c.apiLabel = :apiLabel AND c.repoName IN :repoNames "
			+ "ORDER BY s.endDate DESC, s.id DESC")
	List<ResultRow> findResultRowsForRepository(String apiLabel, Set<String> repoNames,
			Pageable page);

	@Query("SELECT COUNT(s) FROM PullRequestScanEntity s JOIN s.container c "
			+ "WHERE c.apiLabel = :apiLabel AND c.repoName IN :repoNames")
	long countResultRowsForRepository(String apiLabel, Set<String> repoNames);

	interface ResultRow {
		long getId();
		ScanStatus getStatus();
		long getSubmitDate();
		long getStartDate();
		long getEndDate();
		String getScannerExecutionsJson();
		String getScannerTimingsJson();
		String getProviderSummaryJson();
		String getRepoName();
		String getPrId();
		String getApiLabel();
		boolean isResolved();
	}
    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.data.jpa.repository.Query("update PullRequestScanEntity s set s.providerSummaryJson = :json where s.id = :id")
    int updateProviderSummary(@org.springframework.data.repository.query.Param("id") long id, @org.springframework.data.repository.query.Param("json") String json);


    @Query(value = "SELECT p FROM PullRequestScanEntity AS p WHERE p.mcrStatus = ?1 AND p.submitDate = (SELECT MAX(p2.submitDate) FROM PullRequestScanEntity AS p2 WHERE p2.container = p.container)",
            countQuery = "SELECT COUNT(p) FROM PullRequestScanEntity AS p WHERE p.mcrStatus = ?1 AND p.submitDate = (SELECT MAX(p2.submitDate) FROM PullRequestScanEntity AS p2 WHERE p2.container = p.container)")
    Page<PullRequestScanEntity> findLatestMcrsPerPRByMcrStatus(PullRequestMCRStatus mcrStatus, Pageable pageable);

    @Query(value = "SELECT p FROM PullRequestScanEntity AS p WHERE p.mcrStatus <> ?1 AND p.mcrStatus IS NOT NULL AND p.submitDate = (SELECT MAX(p2.submitDate) FROM PullRequestScanEntity AS p2 WHERE p2.container = p.container)",
            countQuery = "SELECT COUNT(p) FROM PullRequestScanEntity AS p WHERE p.mcrStatus <> ?1 AND p.mcrStatus IS NOT NULL AND p.submitDate = (SELECT MAX(p2.submitDate) FROM PullRequestScanEntity AS p2 WHERE p2.container = p.container)")
    Page<PullRequestScanEntity> findLatestMcrsPerPR(PullRequestMCRStatus mcrStatus, Pageable pageable);

    // Excludes 0 (the default for scans that predate item 6.3/6.4, or whose collectFiles()
    // failed before any size could be measured) so they don't drag the average down.
    @Query("SELECT AVG(p.sourceSizeBytes) FROM PullRequestScanEntity AS p WHERE p.sourceSizeBytes > 0")
    Double findAverageSourceSizeBytes();

	@Query("SELECT COUNT(p), COALESCE(AVG(p.totalDurationMs), 0), "
			+ "COALESCE(AVG(p.queueWaitDurationMs), 0), "
			+ "COALESCE(AVG(p.sourcePreparationDurationMs), 0), "
			+ "COALESCE(AVG(p.scannerExecutionDurationMs), 0), "
			+ "COALESCE(AVG(p.resultProcessingDurationMs), 0), "
			+ "COALESCE(AVG(p.scmReportingDurationMs), 0), "
			+ "COALESCE(AVG(p.persistenceDurationMs), 0), "
			+ "COALESCE(AVG(p.cleanupDurationMs), 0) "
			+ "FROM PullRequestScanEntity p WHERE p.performanceComplete = true "
			+ "AND p.endDate >= ?1")
	Object[] findPerformanceSummarySince(long sinceMillis);

	/**
	 * Scans that ended since {@code since}, and the ones still running (end date 0): the results
	 * page's default window, read through idx_pr_scans_end_date.
	 */
	@Query(value = "SELECT s FROM PullRequestScanEntity s WHERE s.endDate >= ?1 OR s.endDate = 0",
			countQuery = "SELECT COUNT(s) FROM PullRequestScanEntity s "
					+ "WHERE s.endDate >= ?1 OR s.endDate = 0")
	Page<PullRequestScanEntity> findEndedSince(long since, Pageable pageable);

	/** Scans that ended before {@code before}. */
	@Query(value = "SELECT s FROM PullRequestScanEntity s WHERE s.endDate > 0 AND s.endDate < ?1",
			countQuery = "SELECT COUNT(s) FROM PullRequestScanEntity s "
					+ "WHERE s.endDate > 0 AND s.endDate < ?1")
	Page<PullRequestScanEntity> findEndedBefore(long before, Pageable pageable);

	/** {@link #findEndedSince} narrowed to scans with findings (manual-review matches apart). */
	@Query(value = "SELECT s FROM PullRequestScanEntity s WHERE (s.endDate >= ?1 OR s.endDate = 0)"
			+ " AND EXISTS (SELECT 1 FROM PullRequestViolationEntity v WHERE v.scan = s"
			+ " AND v.violationName NOT LIKE 'MCR Match:%')",
			countQuery = "SELECT COUNT(s) FROM PullRequestScanEntity s"
					+ " WHERE (s.endDate >= ?1 OR s.endDate = 0)"
					+ " AND EXISTS (SELECT 1 FROM PullRequestViolationEntity v WHERE v.scan = s"
					+ " AND v.violationName NOT LIKE 'MCR Match:%')")
	Page<PullRequestScanEntity> findWithFindingsEndedSince(long since, Pageable pageable);

	/** {@link #findEndedBefore} narrowed to scans with findings (manual-review matches apart). */
	@Query(value = "SELECT s FROM PullRequestScanEntity s WHERE s.endDate > 0 AND s.endDate < ?1"
			+ " AND EXISTS (SELECT 1 FROM PullRequestViolationEntity v WHERE v.scan = s"
			+ " AND v.violationName NOT LIKE 'MCR Match:%')",
			countQuery = "SELECT COUNT(s) FROM PullRequestScanEntity s"
					+ " WHERE s.endDate > 0 AND s.endDate < ?1"
					+ " AND EXISTS (SELECT 1 FROM PullRequestViolationEntity v WHERE v.scan = s"
					+ " AND v.violationName NOT LIKE 'MCR Match:%')")
	Page<PullRequestScanEntity> findWithFindingsEndedBefore(long before, Pageable pageable);

	/**
	 * The newest scan of each given pull request, with its findings counted as its report counts
	 * them (manual-code-review matches apart). Two scans submitted in the same millisecond both
	 * come back; the caller keeps the higher id.
	 */
	@Query("SELECT s.container.id AS containerId, s.id AS scanId, s.status AS status, "
			+ "s.blocked AS blocked, (SELECT COUNT(v) FROM PullRequestViolationEntity v "
			+ "WHERE v.scan = s AND v.violationName NOT LIKE 'MCR Match:%') AS findings "
			+ "FROM PullRequestScanEntity s WHERE s.container.id IN ?1 AND s.submitDate = "
			+ "(SELECT MAX(s2.submitDate) FROM PullRequestScanEntity s2 "
			+ "WHERE s2.container = s.container)")
	List<LatestScan> findLatestByContainerIds(Collection<Long> containerIds);

	/**
	 * Every scan of the given pull requests, as the merge gate view weighs them.
	 */
	@Query("SELECT s.container.id AS containerId, s.id AS scanId, s.commitHash AS commitHash, "
			+ "s.status AS status, CASE WHEN s.remoteAssessmentState = 'COMPLETE' THEN s.remoteCompletedAt WHEN s.remoteAssessmentState IS NOT NULL THEN 0 ELSE s.endDate END AS endDate, s.blocked AS blocked "
			+ "FROM PullRequestScanEntity s WHERE s.container.id IN ?1")
	List<GateScan> findGateScansByContainerIds(Collection<Long> containerIds);

	/**
	 * A scan, as the merge gate view weighs it.
	 */
	interface GateScan {
		long getContainerId();

		long getScanId();

		String getCommitHash();

		ScanStatus getStatus();

		long getEndDate();

		boolean isBlocked();
	}

	/**
	 * A pull request's newest scan.
	 */
	interface LatestScan {
		long getContainerId();

		long getScanId();

		ScanStatus getStatus();

		boolean isBlocked();

		long getFindings();
	}
}
