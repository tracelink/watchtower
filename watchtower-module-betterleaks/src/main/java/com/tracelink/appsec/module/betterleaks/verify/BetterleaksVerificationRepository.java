package com.tracelink.appsec.module.betterleaks.verify;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * Verifications, and the worker's claim/lease operations on them. Claiming is a conditional
 * update, so two Watchtower instances can never run the same check.
 *
 * @author Watchtower
 */
public interface BetterleaksVerificationRepository
		extends JpaRepository<BetterleaksVerificationEntity, Long> {

	Optional<BetterleaksVerificationEntity> findByViolationId(long violationId);

	List<BetterleaksVerificationEntity> findByViolationIdIn(Collection<Long> violationIds);

	/**
	 * @return how many checks the user last requested since then (a re-request replaces the
	 *         requester), for the per-user budget
	 */
	long countByRequestedByAndRequestedAtGreaterThan(String requestedBy, long since);

	List<BetterleaksVerificationEntity> findTop10ByStateAndNextAttemptAtLessThanEqualOrderByNextAttemptAtAsc(
			BetterleaksVerificationState state, long now);

	/**
	 * @return 1 if this caller claimed the verification, 0 if another did or it is not due
	 */
	@Modifying
	@Transactional
	@Query("UPDATE BetterleaksVerificationEntity v SET v.state = :running,"
			+ " v.leaseUntil = :leaseUntil, v.attempts = v.attempts + 1"
			+ " WHERE v.id = :id AND v.state = :pending AND v.nextAttemptAt <= :now")
	int claim(@Param("id") long id, @Param("now") long now, @Param("leaseUntil") long leaseUntil,
			@Param("pending") BetterleaksVerificationState pending,
			@Param("running") BetterleaksVerificationState running);

	/**
	 * Returns checks whose worker died mid-run (instance restart, crash) to the queue.
	 *
	 * @return how many were released
	 */
	@Modifying
	@Transactional
	@Query("UPDATE BetterleaksVerificationEntity v SET v.state = :pending, v.leaseUntil = NULL"
			+ " WHERE v.state = :running AND v.leaseUntil < :now")
	int releaseExpiredLeases(@Param("now") long now,
			@Param("pending") BetterleaksVerificationState pending,
			@Param("running") BetterleaksVerificationState running);
}
