package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * Repository of pull request bypass requests.
 *
 * @author Watchtower
 */
public interface PullRequestBypassRequestRepository
		extends JpaRepository<PullRequestBypassRequestEntity, Long> {

	/**
	 * @return the PR's newest request in that status
	 */
	Optional<PullRequestBypassRequestEntity>
			findFirstByApiLabelAndRepoNameAndPrIdAndStatusOrderByCreatedAtDesc(String apiLabel,
					String repoName, String prId, BypassRequestStatus status);

	/**
	 * @return every pending request: only those have a pending key, which is indexed
	 */
	List<PullRequestBypassRequestEntity> findByPendingKeyIsNotNull();

	/**
	 * @return the newest requests, whatever their status
	 */
	List<PullRequestBypassRequestEntity> findTop200ByOrderByCreatedAtDesc();

	/**
	 * Decides a request atomically: only one of two concurrent decisions wins.
	 *
	 * @param pending {@link BypassRequestStatus#PENDING}
	 * @return 1 if this caller decided it, 0 if it was no longer pending
	 */
	@Modifying(clearAutomatically = true)
	@Transactional
	@Query("UPDATE PullRequestBypassRequestEntity r SET r.status = :outcome,"
			+ " r.decidedBy = :user, r.decidedAt = :decidedAt, r.decisionNote = :note,"
			+ " r.pendingKey = NULL WHERE r.id = :id AND r.status = :pending")
	int close(@Param("id") long id, @Param("outcome") BypassRequestStatus outcome,
			@Param("user") String user, @Param("decidedAt") long decidedAt,
			@Param("note") String note, @Param("pending") BypassRequestStatus pending);

	/**
	 * Undoes {@link #close} when the decision could not be carried out (an approval whose bypass
	 * was refused).
	 *
	 * @param pendingKey the request's {@link PullRequestBypassRequestEntity#pendingKey}
	 * @param closedAs   the status it was closed with
	 * @param pending    {@link BypassRequestStatus#PENDING}
	 * @return 1 if reopened
	 */
	@Modifying(clearAutomatically = true)
	@Transactional
	@Query("UPDATE PullRequestBypassRequestEntity r SET r.status = :pending, r.decidedBy = NULL,"
			+ " r.decidedAt = NULL, r.decisionNote = NULL, r.pendingKey = :pendingKey"
			+ " WHERE r.id = :id AND r.status = :closedAs")
	int reopen(@Param("id") long id, @Param("pendingKey") String pendingKey,
			@Param("closedAs") BypassRequestStatus closedAs,
			@Param("pending") BypassRequestStatus pending);
}
