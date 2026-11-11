package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.scan.ScanType;

/**
 * Repository JPA for the SCM repository entities
 *
 * @author csmith
 */
@Repository(value = "repoRepository")
public interface RepositoryRepository extends JpaRepository<RepositoryEntity, Long>,
		JpaSpecificationExecutor<RepositoryEntity> {

	Page<RepositoryEntity> findByScanTypeAndApiLabelAndEnabledTrueAndRepoNameContainingIgnoreCase(
			ScanType scanType, String apiLabel, String repoName, Pageable pageable);

	RepositoryEntity findByApiLabelAndRepoName(String apiLabel, String repoName);

	List<RepositoryEntity> findByScanType(ScanType scanType);

	/**
	 * @return every integration (api label) that has repositories of this scan type, sorted
	 */
	@Query("select distinct r.apiLabel from RepositoryEntity r where r.scanType = :scanType"
			+ " order by r.apiLabel")
	List<String> findApiLabelsByScanType(@Param("scanType") ScanType scanType);

	Page<RepositoryEntity> findByScanTypeAndApiLabelAndRepoNameContainingIgnoreCase(
			ScanType scanType, String apiLabel, String repoName, Pageable pageable);

	List<RepositoryEntity> findByLastReviewedDateBefore(long lastReviewedDateCutoffMillis);

	/**
	 * @return the distinct stored label sets ({@code ,a,b,}) of an integration's repositories,
	 *         for the label menu
	 */
	@Query("select distinct r.labels from RepositoryEntity r where r.scanType = :scanType"
			+ " and r.apiLabel = :apiLabel and r.labels is not null")
	List<String> findLabelSets(@Param("scanType") ScanType scanType,
			@Param("apiLabel") String apiLabel);

	/**
	 * @return rows of (api label, repository count), from the (api_label, repo_name) index
	 */
	@Query("select r.apiLabel, count(r) from RepositoryEntity r group by r.apiLabel")
	List<Object[]> countByApiLabel();

	/**
	 * @return rows of (api label, first repository name, repository count), so a delete confirm can
	 *         name an integration's only repository
	 */
	@Query("select r.apiLabel, min(r.repoName), count(r) from RepositoryEntity r group by r.apiLabel")
	List<Object[]> firstNameByApiLabel();

	/**
	 * Pauses or resumes many repositories in one statement, touching nothing else on the rows.
	 *
	 * @return how many rows changed
	 */
	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("update RepositoryEntity r set r.configurationVersion = r.configurationVersion + 1, r.scanningPaused = :paused where r.id in :ids")
	int setScanningPaused(@Param("ids") List<Long> ids, @Param("paused") boolean paused);

	@Query("select r.id from RepositoryEntity r where r.apiLabel = :apiLabel")
	List<Long> findIdsByApiLabel(@Param("apiLabel") String apiLabel);

	/**
	 * @return when a catalog sync last listed a repository of the integration, null if never
	 */
	@Query("select max(r.scmSyncedAt) from RepositoryEntity r where r.apiLabel = :apiLabel")
	Long findLastSync(@Param("apiLabel") String apiLabel);

	List<RepositoryEntity> findByScanTypeAndApiLabelAndEnabledTrue(ScanType scanType,
			String apiLabel);

	/**
	 * @param labelPattern {@code ,label,} so one label matches exactly (see RepoLabels)
	 */
	Page<RepositoryEntity> findByScanTypeAndApiLabelAndRepoNameContainingIgnoreCaseAndLabelsContaining(
			ScanType scanType, String apiLabel, String repoName, String labelPattern,
			Pageable pageable);
}
