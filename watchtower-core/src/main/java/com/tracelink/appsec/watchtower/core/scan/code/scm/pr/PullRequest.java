package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import com.tracelink.appsec.watchtower.core.rest.scan.AbstractScan;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;

/**
 * Contains all information about a Pull Request to be used to kick off a scan
 *
 * @author csmith
 */
public class PullRequest extends AbstractScan {

	private PullRequestState prState;
	private String author;
	private String sourceBranch;
	private String destinationBranch;
	private String prId;
	private String repoName;
	private String commitHash;
	private long updateTime;

	public PullRequest(String apiLabel) {
		super(apiLabel);
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

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void populateFromRequest(String requestBody) {
		JSONObject json = new JSONObject(requestBody);
		String repoName = json.getString("repo");
		String prId = json.getString("prid");
		setRepoName(repoName);
		setPrId(prId);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getScanName() {
		return getPRString();
	}
}
