package com.tracelink.appsec.watchtower.core.job;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Background jobs. Like scans, a job is claimed with a conditional update, so a queue message
 * delivered to two pods runs once.
 *
 * @author Watchtower
 */
@Repository
public interface AsyncJobRepository extends JpaRepository<AsyncJobEntity, Long> {

	AsyncJobEntity findByDedupKey(String dedupKey);

	/**
	 * @return the newest job of a type with exactly this payload, or null; how a page finds the
	 *         preparation job of one scan run
	 */
	AsyncJobEntity findFirstByTypeAndPayloadOrderByIdDesc(AsyncJobType type, String payload);

	/**
	 * @return 1 if the caller now runs the job: it was queued, or its runner stopped sending
	 *         heartbeats; 0 otherwise
	 */
	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("UPDATE AsyncJobEntity j SET j.status = :running, j.startedAt = :now,"
			+ " j.heartbeatAt = :now WHERE j.id = :id AND (j.status = :queued"
			+ " OR (j.status = :running AND j.heartbeatAt < :staleBefore))")
	int claim(@Param("id") long id, @Param("now") long now,
			@Param("staleBefore") long staleBefore, @Param("queued") AsyncJobStatus queued,
			@Param("running") AsyncJobStatus running);

	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("UPDATE AsyncJobEntity j SET j.heartbeatAt = :now,"
			+ " j.progress = COALESCE(:progress, j.progress)"
			+ " WHERE j.id = :id AND j.status = :running")
	int heartbeat(@Param("id") long id, @Param("now") long now,
			@Param("progress") String progress, @Param("running") AsyncJobStatus running);

	/**
	 * Ends a job and frees its dedup key, so the same work can be queued again.
	 */
	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("UPDATE AsyncJobEntity j SET j.status = :status, j.finishedAt = :now,"
			+ " j.dedupKey = NULL, j.error = :error, j.resultKey = :resultKey"
			+ " WHERE j.id = :id")
	int finish(@Param("id") long id, @Param("status") AsyncJobStatus status,
			@Param("now") long now, @Param("error") String error,
			@Param("resultKey") String resultKey);

	List<AsyncJobEntity> findTop50ByStatusInOrderByCreatedAtAsc(List<AsyncJobStatus> statuses);

	List<AsyncJobEntity> findTop20ByStatusInOrderByFinishedAtDesc(List<AsyncJobStatus> statuses);

	List<AsyncJobEntity> findTop20ByStatusInAndTypeInOrderByFinishedAtDesc(List<AsyncJobStatus> statuses,
			List<AsyncJobType> types);

	long countByStatus(AsyncJobStatus status);

	/** @return whether a job of the type created after {@code since} is in one of the statuses, such as a sync that is queued or running */
	boolean existsByTypeAndStatusInAndCreatedAtGreaterThan(AsyncJobType type,
			java.util.Collection<AsyncJobStatus> statuses, long since);

	/**
	 * Fails jobs of these types that have waited in the queue since before {@code before} without
	 * ever starting, which also frees their dedup key so the work can be queued again.
	 *
	 * @return how many were failed
	 */
	@Modifying(clearAutomatically = true, flushAutomatically = true)
	@Transactional
	@Query("UPDATE AsyncJobEntity j SET j.status = com.tracelink.appsec.watchtower.core.job.AsyncJobStatus.FAILED,"
			+ " j.finishedAt = :now, j.dedupKey = NULL, j.error = :error"
			+ " WHERE j.status = com.tracelink.appsec.watchtower.core.job.AsyncJobStatus.QUEUED"
			+ " AND j.type IN :types AND j.createdAt < :before")
	int expireQueued(@Param("types") List<AsyncJobType> types, @Param("before") long before,
			@Param("now") long now, @Param("error") String error);

 @Query("SELECT j.id FROM AsyncJobEntity j WHERE j.finishedAt < :before ORDER BY j.id")
 List<Long> findFinishedBefore(@Param("before") long before,org.springframework.data.domain.Pageable page);

 @Modifying(clearAutomatically=true,flushAutomatically=true)
 @Transactional
 @Query("DELETE FROM AsyncJobEntity j WHERE j.id IN :ids AND j.finishedAt < :before")
 int deleteFinishedIds(@Param("ids") List<Long> ids,@Param("before") long before);

 @Transactional
 default int deleteFinishedBefore(long before) {
  var ids=findFinishedBefore(before,org.springframework.data.domain.PageRequest.of(0,1000));
  return ids.isEmpty()?0:deleteFinishedIds(ids,before);
 }
}
