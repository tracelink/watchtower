package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import org.apache.commons.lang3.StringUtils;

/**
 * Contains all information about a Pull Request to be used to kick off a scan
 *
 * @author csmith
 */
public class PullRequest {
	private String apiLabel;
	private PullRequestState prState;
	private String author;
	private String sourceBranch;
	private String destinationBranch;
	private String prId;
	private String repoName;
	private String commitHash;
	private long updateTime;
	private long submitTime;

	public PullRequest(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getApiLabel() {
		return this.apiLabel;
	}

	public void setState(PullRequestState state) {
		this.prState = state;
	}

	public PullRequestState getState() {
		return this.prState;
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

	public String getPRString() {
		return repoName + "-" + prId;
	}

	public String getCommitHash() {
		return commitHash;
	}

	public void setCommitHash(String commitHash) {
		this.commitHash = commitHash;
	}

	public long getUpdateTime() {
		return updateTime;
	}

	public void setUpdateTime(long updateTime) {
		this.updateTime = updateTime;
	}

	public long getSubmitTime() {
		return submitTime;
	}

	public void setSubmitTime(long submitTime) {
		this.submitTime = submitTime;
	}

	/**
	 * Checks that all data members have some data (does not check whether that data is valid)
	 *
	 * @return true if all data members are filled out with information, false otherwise
	 */
	public boolean hasAllData() {
		return StringUtils.isNotBlank(getAuthor()) && StringUtils.isNotBlank(getSourceBranch())
				&& StringUtils.isNotBlank(getDestinationBranch())
				&& StringUtils.isNotBlank(getRepoName())
				&& StringUtils.isNotBlank(getPrId())
				&& StringUtils.isNotBlank(getCommitHash())
				&& getUpdateTime() > 0L;
	}
}
