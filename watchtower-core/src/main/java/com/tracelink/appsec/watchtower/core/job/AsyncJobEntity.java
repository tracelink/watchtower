package com.tracelink.appsec.watchtower.core.job;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One piece of background work and how it went, so the queue view can show what is waiting,
 * running, and what failed. The work itself travels as a queue message naming this row.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "async_jobs")
public class AsyncJobEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "job_id")
	private long id;

	@Enumerated(EnumType.STRING)
	@Column(name = "job_type")
	private AsyncJobType type;

	@Enumerated(EnumType.STRING)
	@Column(name = "status")
	private AsyncJobStatus status;

	/** Set only while queued or running, so a duplicate job is refused until this finishes. */
	@Column(name = "dedup_key")
	private String dedupKey;

	/** Small JSON describing the work; never source code. */
	@Column(name = "payload")
	private String payload;

	@Column(name = "progress")
	private String progress;

	@Column(name = "result_key")
	private String resultKey;

	@Column(name = "error")
	private String error;

	@Column(name = "created_by")
	private String createdBy;

	@Column(name = "created_at")
	private long createdAt;

	@Column(name = "started_at")
	private Long startedAt;

	@Column(name = "finished_at")
	private Long finishedAt;

	@Column(name = "heartbeat_at")
	private Long heartbeatAt;

	public long getId() {
		return id;
	}

	public AsyncJobType getType() {
		return type;
	}

	public void setType(AsyncJobType type) {
		this.type = type;
	}

	public AsyncJobStatus getStatus() {
		return status;
	}

	public void setStatus(AsyncJobStatus status) {
		this.status = status;
	}

	public String getDedupKey() {
		return dedupKey;
	}

	public void setDedupKey(String dedupKey) {
		this.dedupKey = dedupKey;
	}

	public String getPayload() {
		return payload;
	}

	public void setPayload(String payload) {
		this.payload = payload;
	}

	public String getProgress() {
		return progress;
	}

	public void setProgress(String progress) {
		this.progress = progress;
	}

	public String getResultKey() {
		return resultKey;
	}

	public void setResultKey(String resultKey) {
		this.resultKey = resultKey;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public String getCreatedBy() {
		return createdBy;
	}

	public void setCreatedBy(String createdBy) {
		this.createdBy = createdBy;
	}

	public long getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(long createdAt) {
		this.createdAt = createdAt;
	}

	public long getStartedAt() {
		return startedAt == null ? 0 : startedAt;
	}

	public long getFinishedAt() {
		return finishedAt == null ? 0 : finishedAt;
	}

	public long getHeartbeatAt() {
		return heartbeatAt == null ? 0 : heartbeatAt;
	}
}
