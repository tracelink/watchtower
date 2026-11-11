package com.tracelink.appsec.module.betterleaks.verify;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A request to verify one pull request violation's secret live, and its result. Also the job
 * the worker claims. Holds no secret, match or hash of either. Times are epoch milliseconds.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "betterleaks_verifications")
public class BetterleaksVerificationEntity {

	/** The longest error text stored; errors are Watchtower's own messages, never tool output. */
	static final int MAX_ERROR_LENGTH = 300;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "verification_id")
	private long id;

	@Column(name = "violation_id")
	private long violationId;

	@Column(name = "state")
	@Enumerated(EnumType.STRING)
	private BetterleaksVerificationState state;

	@Column(name = "attempts")
	private int attempts;

	@Column(name = "next_attempt_at")
	private long nextAttemptAt;

	@Column(name = "lease_until")
	private Long leaseUntil;

	@Column(name = "requested_by")
	private String requestedBy;

	@Column(name = "requested_at")
	private long requestedAt;

	@Column(name = "verified_at")
	private Long verifiedAt;

	@Column(name = "notified_at")
	private Long notifiedAt;

	@Column(name = "last_error")
	private String lastError;

	public long getId() {
		return id;
	}

	public long getViolationId() {
		return violationId;
	}

	public void setViolationId(long violationId) {
		this.violationId = violationId;
	}

	public BetterleaksVerificationState getState() {
		return state;
	}

	public void setState(BetterleaksVerificationState state) {
		this.state = state;
	}

	public int getAttempts() {
		return attempts;
	}

	public void setAttempts(int attempts) {
		this.attempts = attempts;
	}

	public long getNextAttemptAt() {
		return nextAttemptAt;
	}

	public void setNextAttemptAt(long nextAttemptAt) {
		this.nextAttemptAt = nextAttemptAt;
	}

	public Long getLeaseUntil() {
		return leaseUntil;
	}

	public void setLeaseUntil(Long leaseUntil) {
		this.leaseUntil = leaseUntil;
	}

	public String getRequestedBy() {
		return requestedBy;
	}

	public void setRequestedBy(String requestedBy) {
		this.requestedBy = requestedBy;
	}

	public long getRequestedAt() {
		return requestedAt;
	}

	public void setRequestedAt(long requestedAt) {
		this.requestedAt = requestedAt;
	}

	public Long getVerifiedAt() {
		return verifiedAt;
	}

	public void setVerifiedAt(Long verifiedAt) {
		this.verifiedAt = verifiedAt;
	}

	public Long getNotifiedAt() {
		return notifiedAt;
	}

	public void setNotifiedAt(Long notifiedAt) {
		this.notifiedAt = notifiedAt;
	}

	public String getLastError() {
		return lastError;
	}

	public void setLastError(String lastError) {
		this.lastError = lastError == null || lastError.length() <= MAX_ERROR_LENGTH ? lastError
				: lastError.substring(0, MAX_ERROR_LENGTH);
	}
}
