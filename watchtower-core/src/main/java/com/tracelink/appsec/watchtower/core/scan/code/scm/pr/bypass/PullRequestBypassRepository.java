package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Repository of pull request bypasses.
 *
 * @author Watchtower
 */
public interface PullRequestBypassRepository extends JpaRepository<PullRequestBypassEntity, Long> {

	/**
	 * @param apiLabel the SCM integration
	 * @param repoName the repository
	 * @param prId     the pull request
	 * @return the PR's bypasses that are not revoked, newest first
	 */
	@Query("SELECT DISTINCT b FROM PullRequestBypassEntity b WHERE b.apiLabel = :apiLabel"
			+ " AND b.repoName = :repoName AND b.prId = :prId AND b.revokedAt IS NULL"
			+ " ORDER BY b.createdAt DESC, b.id DESC")
	List<PullRequestBypassEntity> findActive(@Param("apiLabel") String apiLabel,
			@Param("repoName") String repoName, @Param("prId") String prId);

	/**
	 * @return every bypass that is not revoked, newest first
	 */
	List<PullRequestBypassEntity> findByRevokedAtIsNullOrderByCreatedAtDesc();

	/**
	 * @return the 200 newest bypasses, revoked or not
	 */
	List<PullRequestBypassEntity> findTop200ByOrderByCreatedAtDesc();

	/**
	 * @param since epoch millis
	 * @return when each bypass still active at that time, or made since, was in force
	 */
	@Query("SELECT b.apiLabel AS apiLabel, b.repoName AS repoName, b.prId AS prId, "
			+ "b.createdAt AS createdAt, b.revokedAt AS revokedAt FROM PullRequestBypassEntity b "
			+ "WHERE b.revokedAt IS NULL OR b.revokedAt >= :since")
	List<BypassWindow> findWindowsSince(@Param("since") long since);

	/**
	 * When one bypass was in force.
	 */
	interface BypassWindow {
		String getApiLabel();

		String getRepoName();

		String getPrId();

		long getCreatedAt();

		Long getRevokedAt();
	}

	/**
	 * @param since epoch millis
	 * @return bypasses made since then per repository, most first
	 */
	@Query("SELECT new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass"
			+ ".RepoBypassCount(b.apiLabel, b.repoName, COUNT(b))"
			+ " FROM PullRequestBypassEntity b WHERE b.createdAt >= :since"
			+ " GROUP BY b.apiLabel, b.repoName ORDER BY COUNT(b) DESC, b.repoName")
	List<RepoBypassCount> countPerRepositorySince(@Param("since") long since);
}
