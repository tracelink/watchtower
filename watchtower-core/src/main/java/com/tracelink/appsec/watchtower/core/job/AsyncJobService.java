package com.tracelink.appsec.watchtower.core.job;

import java.time.Clock;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.RepoWorkQueue;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.WorkOutcome;

/**
 * Creates, queues and runs background jobs. A job row is written first and the queue message
 * names it, so the queue view always shows a job even while its message is in flight, and a
 * message delivered twice runs the job once.
 *
 * @author Watchtower
 */
@Service
public class AsyncJobService {

	private static final Logger LOG = LoggerFactory.getLogger(AsyncJobService.class);

	/** A running job whose heartbeat is older than this is taken to have died with its pod. */
	static final long STALE_AFTER_MILLIS = 3 * 60_000L;

	private static final int MAX_ERROR_LENGTH = 500;

	private static final int MAX_PROGRESS_LENGTH = 255;

	private static final int RETRY_RUNNING_ELSEWHERE_SECONDS = 60;

	/** SQS FIFO group ids are at most 128 characters of a limited set. */
	private static final int MAX_GROUP_LENGTH = 128;

	private final AsyncJobRepository jobs;

	private final RepoWorkQueue queue;

	private final Map<AsyncJobType, AsyncJobHandler> handlers = new EnumMap<>(AsyncJobType.class);

	private final Clock clock;

	@Autowired
	public AsyncJobService(AsyncJobRepository jobs, RepoWorkQueue queue,
			List<AsyncJobHandler> handlers) {
		this(jobs, queue, handlers, Clock.systemUTC());
	}

	AsyncJobService(AsyncJobRepository jobs, RepoWorkQueue queue, List<AsyncJobHandler> handlers,
			Clock clock) {
		this.jobs = jobs;
		this.queue = queue;
		this.clock = clock;
		handlers.forEach(handler -> this.handlers.put(handler.type(), handler));
	}

	/**
	 * Records and queues a job.
	 *
	 * @param type     the job type
	 * @param payload  small JSON describing the work, no source or secrets
	 * @param dedupKey refuses this job while another with the same key is queued or running;
	 *                 null for no dedup
	 * @param user     who asked for it, or null for the system
	 * @return the job, or empty if an identical job is already queued or running
	 */
	public Optional<AsyncJobEntity> enqueue(AsyncJobType type, String payload, String dedupKey,
			String user) {
		AsyncJobEntity job = new AsyncJobEntity();
		job.setType(type);
		job.setStatus(AsyncJobStatus.QUEUED);
		job.setDedupKey(dedupKey);
		job.setPayload(payload);
		job.setCreatedBy(user);
		job.setCreatedAt(clock.millis());
		try {
			job = jobs.saveAndFlush(job);
		} catch (DataIntegrityViolationException e) {
			LOG.info("A {} job with key {} is already queued or running", type, dedupKey);
			return Optional.empty();
		}
		if (!queue.sendJob(job.getId(), groupOf(job))) {
			jobs.finish(job.getId(), AsyncJobStatus.FAILED, clock.millis(),
					"Could not queue the job", null);
			return Optional.empty();
		}
		return Optional.of(job);
	}

	/**
	 * Runs a queued job: claims it, hands it to its handler, and records how it ended.
	 *
	 * @param jobId the job to run
	 * @return what to do with the job's queue message
	 */
	public WorkOutcome run(long jobId) {
		long now = clock.millis();
		if (jobs.claim(jobId, now, now - STALE_AFTER_MILLIS, AsyncJobStatus.QUEUED,
				AsyncJobStatus.RUNNING) == 0) {
			return jobs.findById(jobId).filter(j -> !j.getStatus().isFinished())
					.map(j -> WorkOutcome.retryLater(RETRY_RUNNING_ELSEWHERE_SECONDS))
					.orElse(WorkOutcome.done());
		}
		AsyncJobEntity job = jobs.findById(jobId).orElse(null);
		AsyncJobHandler handler = job == null ? null : handlers.get(job.getType());
		if (handler == null) {
			jobs.finish(jobId, AsyncJobStatus.FAILED, clock.millis(),
					"No handler for this job type", null);
			return WorkOutcome.done();
		}
		try {
			String result = handler.handle(job, note -> progress(jobId, note));
			jobs.finish(jobId, AsyncJobStatus.DONE, clock.millis(), null, result);
			return WorkOutcome.done();
		} catch (RetryLaterException e) {
			LOG.info("{} job {} will retry in {}s: {}", job.getType(), jobId,
					e.getDelaySeconds(), e.getMessage());
			job.setStatus(AsyncJobStatus.QUEUED);
			jobs.saveAndFlush(job);
			return WorkOutcome.retryLater(e.getDelaySeconds());
		} catch (Exception e) {
			LOG.error(job.getType() + " job " + jobId + " failed", e);
			jobs.finish(jobId, AsyncJobStatus.FAILED, clock.millis(), describe(e), null);
			return WorkOutcome.done();
		}
	}

	/**
	 * Refreshes a running job's heartbeat, and its progress note if given.
	 */
	public void progress(long jobId, String note) {
		jobs.heartbeat(jobId, clock.millis(), StringUtils.abbreviate(note, MAX_PROGRESS_LENGTH),
				AsyncJobStatus.RUNNING);
	}

	/**
	 * @return queued and running jobs, oldest first
	 */
	/**
	 * How long a sync or check may wait or run before it is treated as lost: far longer than either
	 * takes, so only a job whose queue message was never handled is dropped.
	 */
	public static final long STUCK_AFTER_MILLIS = 30 * 60_000L;

	/**
	 * @param within only jobs created this recently count; an older one still waiting is lost, not in progress
	 * @return whether a job of the type is waiting or running, so a page can show it and stop a second request
	 */
	public boolean hasActive(AsyncJobType type, long within) {
		return jobs.existsByTypeAndStatusInAndCreatedAtGreaterThan(type,
				List.of(AsyncJobStatus.QUEUED, AsyncJobStatus.RUNNING), clock.millis() - within);
	}

	/**
	 * Fails jobs that have waited in the queue longer than {@code maxAge} without starting. A job
	 * whose queue message was lost would otherwise keep its dedup key forever and refuse every
	 * later request for the same work as "already running".
	 *
	 * @return how many were failed
	 */
	public int expireStalledQueued(List<AsyncJobType> types, long maxAge) {
		int expired = jobs.expireQueued(types, clock.millis() - maxAge, clock.millis(),
				"Waited too long without starting; the request was dropped");
		if (expired > 0) {
			LOG.warn("Dropped {} queued {} job(s) that never started", expired, types);
		}
		return expired;
	}

	public List<AsyncJobEntity> getActiveJobs() {
		return jobs.findTop50ByStatusInOrderByCreatedAtAsc(
				List.of(AsyncJobStatus.QUEUED, AsyncJobStatus.RUNNING));
	}

	/**
	 * @return the most recently finished jobs
	 */
	public List<AsyncJobEntity> getRecentJobs() {
		return jobs.findTop20ByStatusInOrderByFinishedAtDesc(
				List.of(AsyncJobStatus.DONE, AsyncJobStatus.FAILED));
	}

	/**
	 * @param types the job types to show; empty for every type
	 * @return the most recently finished jobs of those types
	 */
	public List<AsyncJobEntity> getRecentJobs(List<AsyncJobType> types) {
		return types.isEmpty() ? getRecentJobs()
				: jobs.findTop20ByStatusInAndTypeInOrderByFinishedAtDesc(
						List.of(AsyncJobStatus.DONE, AsyncJobStatus.FAILED), types);
	}

	public Optional<AsyncJobEntity> getJob(long jobId) {
		return jobs.findById(jobId);
	}

	/**
	 * Sends unfinished jobs to the queue again. Only for in-process queues after a restart:
	 * their in-memory work was lost, while SQS keeps its messages.
	 */
	public void requeueUnfinished() {
		for (AsyncJobEntity job : getActiveJobs()) {
			queue.sendJob(job.getId(), groupOf(job));
		}
	}

	/**
	 * @param days finished jobs older than this many days are deleted, up to 1000 a call
	 * @return how many were deleted
	 */
	public int deleteFinishedOlderThan(int days) {
		return jobs.deleteFinishedBefore(clock.millis() - days * 86_400_000L);
	}

	/**
	 * Jobs that must not overlap share a dedup key, and so share a queue group; every other job
	 * gets its own group and runs independently. Characters a FIFO group id does not allow
	 * (spaces, for one) become underscores.
	 */
	static String groupOf(AsyncJobEntity job) {
		String key = job.getDedupKey() == null ? String.valueOf(job.getId()) : job.getDedupKey();
		return StringUtils.left("job-" + key.replaceAll("[^A-Za-z0-9._:-]", "_"),
				MAX_GROUP_LENGTH);
	}

	private static String describe(Exception e) {
		String message = StringUtils.defaultIfBlank(e.getMessage(), e.getClass().getSimpleName());
		return StringUtils.abbreviate(message, MAX_ERROR_LENGTH);
	}
}
