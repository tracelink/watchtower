package com.tracelink.appsec.watchtower.core.alerting.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.alerting.AlertStatus;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertLogEntity;

/**
 * Repository of queued and sent alert messages.
 *
 * @author Watchtower
 */
public interface AlertLogRepository extends JpaRepository<AlertLogEntity, Long> {

	/**
	 * @param status    the status to find
	 * @param dueBefore messages due at or before this time
	 * @return up to 20 due messages, oldest first
	 */
	List<AlertLogEntity> findTop20ByStatusAndNextAttemptAtLessThanEqualOrderByIdAsc(
			AlertStatus status, long dueBefore);

	/**
	 * Leases a due message to one sender by moving its next attempt into the future, so another
	 * Watchtower instance polling at the same time skips it. If the sender dies, the message is
	 * due again when the lease ends.
	 *
	 * @param id         the message
	 * @param expected   its next-attempt time as read
	 * @param leaseUntil when another sender may take it over
	 * @param pending    {@link AlertStatus#PENDING}
	 * @return 1 if this caller claimed it, 0 if another did first
	 */
	@Modifying
	@Transactional
	@Query("UPDATE AlertLogEntity m SET m.nextAttemptAt = :leaseUntil"
			+ " WHERE m.id = :id AND m.status = :pending AND m.nextAttemptAt = :expected")
	int claim(@Param("id") long id, @Param("expected") long expected,
			@Param("leaseUntil") long leaseUntil, @Param("pending") AlertStatus pending);

	/**
	 * @return the 100 most recent messages
	 */
	List<AlertLogEntity> findTop100ByOrderByIdDesc();

	/**
	 * Delivery history, newest first, optionally narrowed to one status and one alert type.
	 *
	 * @param status   a status, or null for all
	 * @param type     an alert type key, or null for all
	 * @param pageable the page to read
	 * @return one page of messages with the total count
	 */
	@Query("SELECT m FROM AlertLogEntity m WHERE (:status IS NULL OR m.status = :status)"
			+ " AND (:type IS NULL OR m.alertType = :type) ORDER BY m.id DESC")
	org.springframework.data.domain.Page<AlertLogEntity> findHistory(@Param("status") AlertStatus status,
			@Param("type") String type, org.springframework.data.domain.Pageable pageable);
}
