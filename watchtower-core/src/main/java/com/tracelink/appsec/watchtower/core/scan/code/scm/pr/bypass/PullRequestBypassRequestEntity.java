package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A request that someone with the bypass privilege stop Watchtower blocking a pull request
 * (§4.17). Kept after it is decided, for the audit trail.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "pull_request_bypass_requests")
public class PullRequestBypassRequestEntity {
 @Column(name="reason_code", length=24)
 @jakarta.persistence.Enumerated(jakarta.persistence.EnumType.STRING)
 private BypassReasonCode reasonCode;
 public BypassReasonCode getReasonCode() { return reasonCode; }
 public void setReasonCode(BypassReasonCode reasonCode) { this.reasonCode=reasonCode; }


	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "request_id")
	private long id;

	@Column(name = "api_label", nullable = false)
	private String apiLabel;

	@Column(name = "repo_name", nullable = false)
	private String repoName;

	@Column(name = "pr_id", nullable = false)
	private String prId;

	/** The scan the request was made on; approving needs it to still be the latest. */
	@Column(name = "scan_id", nullable = false)
	private long scanId;

	@Column(name = "requested_by", nullable = false)
	private String requestedBy;

	@Column(name = "reason", nullable = false, length = PullRequestBypassEntity.MAX_REASON_LENGTH)
	private String reason;

	@Column(name = "created_at", nullable = false)
	private long createdAt;

	@Column(name = "status", nullable = false)
	@Enumerated(EnumType.STRING)
	private BypassRequestStatus status = BypassRequestStatus.PENDING;

	@Column(name = "decided_by")
	private String decidedBy;

	@Column(name = "decided_at")
	private Long decidedAt;

	@Column(name = "decision_note", length = PullRequestBypassEntity.MAX_REASON_LENGTH)
	private String decisionNote;

	/** Set only while pending; unique, so one pull request has at most one pending request. */
	@Column(name = "pending_key", length = 64)
	private String pendingKey;

	@Column(name = "source", nullable = false, length = 16)
	@Enumerated(EnumType.STRING)
	private RequestSource source = RequestSource.WATCHTOWER;

	/** For {@link RequestSource#PR_COMMENT}: the commenter's SCM account id. */
	@Column(name = "requester_scm_id", length = 64)
	private String requesterScmId;

	/**
	 * @return the value {@code pending_key} holds while a request of this pull request is
	 *         pending: a hash, since the three values together are too long to index
	 */
	public static String pendingKey(String apiLabel, String repoName, String prId) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(String.join("\u0000",
					apiLabel, repoName, prId).getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is unavailable", e);
		}
	}

	public String getPendingKey() {
		return pendingKey;
	}

	public RequestSource getSource() {
		return source;
	}

	public void setSource(RequestSource source) {
		this.source = source;
	}

	/**
	 * @return true if the request came from a PR comment, so its requester is an SCM name
	 */
	public boolean isFromPullRequestComment() {
		return source == RequestSource.PR_COMMENT;
	}

	public String getRequesterScmId() {
		return requesterScmId;
	}

	public void setRequesterScmId(String requesterScmId) {
		this.requesterScmId = requesterScmId;
	}

	public void setPendingKey(String pendingKey) {
		this.pendingKey = pendingKey;
	}

	public long getId() {
		return id;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getRepoName() {
		return repoName;
	}

	public void setRepoName(String repoName) {
		this.repoName = repoName;
	}

	public String getPrId() {
		return prId;
	}

	public void setPrId(String prId) {
		this.prId = prId;
	}

	public long getScanId() {
		return scanId;
	}

	public void setScanId(long scanId) {
		this.scanId = scanId;
	}

	public String getRequestedBy() {
		return requestedBy;
	}

	public void setRequestedBy(String requestedBy) {
		this.requestedBy = requestedBy;
	}

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}

	public long getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(long createdAt) {
		this.createdAt = createdAt;
	}

	public BypassRequestStatus getStatus() {
		return status;
	}

	public void setStatus(BypassRequestStatus status) {
		this.status = status;
	}

	public String getDecidedBy() {
		return decidedBy;
	}

	public Long getDecidedAt() {
		return decidedAt;
	}

	public String getDecisionNote() {
		return decisionNote;
	}

	/**
	 * Closes the request.
	 *
	 * @param outcome how it ended; not {@link BypassRequestStatus#PENDING}
	 * @param user    who closed it, or null when Watchtower did (superseded)
	 * @param when    epoch millis
	 * @param note    an optional note, or null
	 */
	public void decide(BypassRequestStatus outcome, String user, long when, String note) {
		if (outcome == BypassRequestStatus.PENDING) {
			throw new IllegalArgumentException("A decision cannot leave a request pending");
		}
		this.status = outcome;
		this.decidedBy = user;
		this.decidedAt = when;
		this.decisionNote = note;
		this.pendingKey = null;
	}
}
