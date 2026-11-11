package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity;

import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;

/**
 * Container Entity class for Pull Requests with reverse join to {@linkplain PullRequestScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "pull_request_container")
public class PullRequestContainerEntity extends AbstractScanContainerEntity<PullRequestScanEntity> {

	@Column(name = "resolved")
	private boolean resolved;

	@Column(name = "api_label")
	private String apiLabel;

	@Column(name = "author")
	private String author;

	@Column(name = "source_branch")
	private String sourceBranch;

	@Column(name = "destination_branch")
	private String destinationBranch;

	@Column(name = "pr_id")
	private String prId;

	@Column(name = "repo_name")
	private String repoName;

	/** MERGED or DECLINED once the SCM says so; null while open and for older rows. */
	@Enumerated(EnumType.STRING)
	@Column(name = "closed_state", length = 16)
	private PullRequestState closedState;

	/** When the SCM says it closed, epoch millis. */
	@Column(name = "closed_at")
	private Long closedAt;

	/** The commit merged, from the SCM. */
	@Column(name = "merged_commit", length = 64)
	private String mergedCommit;

	/** Whether a scan of it was queued or running when the close was seen. */
	@Column(name = "scan_pending_at_close")
	private Boolean scanPendingAtClose;

	@OneToMany(fetch = FetchType.EAGER, mappedBy = "container", cascade = CascadeType.MERGE)
	@OrderBy(value = "end_date DESC")
	private List<PullRequestScanEntity> scans;

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}

	public String getSourceBranch() {
		return sourceBranch;
	}

	public void setSourceBranch(String sourceBranch) {
		this.sourceBranch = sourceBranch;
	}

	public String getDestinationBranch() {
		return destinationBranch;
	}

	public void setDestinationBranch(String destinationBranch) {
		this.destinationBranch = destinationBranch;
	}

	public String getPrId() {
		return prId;
	}

	public void setPrId(String prId) {
		this.prId = prId;
	}

	public String getRepoName() {
		return repoName;
	}

	public void setRepoName(String repoName) {
		this.repoName = repoName;
	}

	public boolean isResolved() {
		return resolved;
	}

	public void setResolved(boolean resolved) {
		this.resolved = resolved;
	}

	public PullRequestContainerEntity() {
		// for auto-configuration in jpa
	}

	/**
	 * create from Pull Request without adding violations or setting the resolved status
	 *
	 * @param pr the Pull Request used as a model
	 */
	public PullRequestContainerEntity(PullRequest pr) {
		this();
		setApiLabel(pr.getApiLabel());
		setAuthor(pr.getAuthor());
		setSourceBranch(pr.getSourceBranch());
		setDestinationBranch(pr.getDestinationBranch());
		setRepoName(pr.getRepoName());
		setPrId(pr.getPrId());
	}

	/**
	 * Converts the data in this object into a {@linkplain PullRequest}
	 * 
	 * @return a Pull Requests using data from this object
	 */
	public PullRequest toPullRequest() {
		PullRequest pr = new PullRequest(getApiLabel());
		pr.setRepoName(getRepoName());
		pr.setPrId(getPrId());
		pr.setAuthor(getAuthor());
		pr.setDestinationBranch(getDestinationBranch());
		pr.setSourceBranch(getSourceBranch());
		return pr;
	}

	@Override
	public List<PullRequestScanEntity> getScans() {
		return scans;
	}

	public PullRequestState getClosedState() {
		return closedState;
	}

	public Long getClosedAt() {
		return closedAt;
	}

	public String getMergedCommit() {
		return mergedCommit;
	}

	public boolean isScanPendingAtClose() {
		return Boolean.TRUE.equals(scanPendingAtClose);
	}

	/**
	 * Records how the pull request closed. The first close seen wins: the webhook, the queue and
	 * the sync can each report the same merge, and later reports must not move its time. A scan
	 * seen pending by any of them still counts. A merge replaces a decline: the pull request was
	 * reopened and merged before Watchtower saw it open again.
	 *
	 * @param state       MERGED or DECLINED; anything else is ignored
	 * @param closedAt    when the SCM says it closed, epoch millis. Bitbucket's update time: the
	 *                    merge time when the merge event reports it, a later time when the sync
	 *                    finds the merge after other activity
	 * @param commit      the commit merged, or null
	 * @param scanPending whether a scan of it was queued or running then
	 */
	public void recordClosed(PullRequestState state, long closedAt, String commit,
			boolean scanPending) {
		if (state == null || !state.isResolved()) {
			return;
		}
		if (closedState == null || (closedState == PullRequestState.DECLINED
				&& state == PullRequestState.MERGED)) {
			this.closedState = state;
			this.closedAt = closedAt;
			this.mergedCommit = state == PullRequestState.MERGED ? commit : null;
			this.scanPendingAtClose = null;
		}
		if (scanPending) {
			this.scanPendingAtClose = true;
		} else if (scanPendingAtClose == null) {
			this.scanPendingAtClose = false;
		}
	}

	/**
	 * Forgets a close when the SCM reports the pull request open again after it. A scan that
	 * started before the close reports it open too, but with an earlier update time, so it does
	 * not erase the merge it raced.
	 *
	 * @param state     the state the SCM reported
	 * @param updatedAt the SCM's update time with that state, epoch millis
	 */
	public void recordOpen(PullRequestState state, long updatedAt) {
		if (state == PullRequestState.ACTIVE && closedAt != null && updatedAt > closedAt) {
			this.closedState = null;
			this.closedAt = null;
			this.mergedCommit = null;
			this.scanPendingAtClose = null;
		}
	}

}
