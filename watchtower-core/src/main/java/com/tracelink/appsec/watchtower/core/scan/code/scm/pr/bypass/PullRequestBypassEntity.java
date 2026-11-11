package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

/**
 * A privileged user's decision to stop Watchtower blocking one pull request, for the findings
 * present at the bypassed scan. Revoking keeps the row for the audit trail.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "pull_request_bypasses")
public class PullRequestBypassEntity {
 @Column(name="reason_code", length=24)
 @jakarta.persistence.Enumerated(jakarta.persistence.EnumType.STRING)
 private BypassReasonCode reasonCode;
 public BypassReasonCode getReasonCode() { return reasonCode; }
 public void setReasonCode(BypassReasonCode reasonCode) { this.reasonCode=reasonCode; }


	/** Matches the {@code reason} column. */
	public static final int MAX_REASON_LENGTH = 1000;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "bypass_id")
	private long id;

	@Column(name = "api_label", nullable = false)
	private String apiLabel;

	@Column(name = "repo_name", nullable = false)
	private String repoName;

	@Column(name = "pr_id", nullable = false)
	private String prId;

	/** The scan whose findings were bypassed. */
	@Column(name = "scan_id", nullable = false)
	private long scanId;

	@Column(name = "commit_hash")
	private String commitHash;

	@Column(name = "bypassed_by", nullable = false)
	private String bypassedBy;

	@Column(name = "reason", nullable = false, length = MAX_REASON_LENGTH)
	private String reason;

	@Column(name = "created_at", nullable = false)
	private long createdAt;

	@Column(name = "revoked_by")
	private String revokedBy;

	@Column(name = "revoked_at")
	private Long revokedAt;

	/** Small (one row per rule and file), and needed wherever the bypass is, so loaded eagerly. */
	@ElementCollection(fetch = FetchType.EAGER)
	@CollectionTable(name = "pull_request_bypass_findings",
			joinColumns = @JoinColumn(name = "bypass_id"))
	private Set<BypassedFinding> findings = new HashSet<>();

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

	public String getCommitHash() {
		return commitHash;
	}

	public void setCommitHash(String commitHash) {
		this.commitHash = commitHash;
	}

	public String getBypassedBy() {
		return bypassedBy;
	}

	public void setBypassedBy(String bypassedBy) {
		this.bypassedBy = bypassedBy;
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

	public String getRevokedBy() {
		return revokedBy;
	}

	public Long getRevokedAt() {
		return revokedAt;
	}

	public boolean isRevoked() {
		return revokedAt != null;
	}

	/**
	 * Ends this bypass; blocking resumes from the next scan.
	 *
	 * @param user who revoked it
	 * @param when epoch millis
	 */
	public void revoke(String user, long when) {
		this.revokedBy = user;
		this.revokedAt = when;
	}

	/**
	 * @return an unmodifiable view of the covered findings
	 */
	public Set<BypassedFinding> getFindings() {
		return Set.copyOf(findings);
	}

	public void setFindings(Set<BypassedFinding> findings) {
		this.findings = new HashSet<>(findings);
	}
}
