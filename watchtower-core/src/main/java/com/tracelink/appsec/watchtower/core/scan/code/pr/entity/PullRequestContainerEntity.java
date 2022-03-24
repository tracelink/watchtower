package com.tracelink.appsec.watchtower.core.scan.code.pr.entity;

import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanContainer;
import com.tracelink.appsec.watchtower.core.scan.code.pr.PullRequest;

/**
 * Container Entity class for Pull Requests with reverse join to {@linkplain PullRequestScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "pull_request_container")
public class PullRequestContainerEntity extends AbstractScanContainer<PullRequestScanEntity> {

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

}
