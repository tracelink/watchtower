package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

/**
 * This is a holder for PullRequest information originating from the UI. It only contains a subset
 * of required data to allow the scan to start.
 *
 * @author csmith
 */
public class ManualPullRequest {
	/*
	 * NOTE: THIS SHOULD NOT BE MADE A SUBCLASS OF PULLREQUEST AS IT DOES NOT CONTAIN ALL REQUIRED
	 * INFORMATION
	 */
	private String apiLabel;
	private String repo;
	private String prid;

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getRepo() {
		return repo;
	}

	public void setRepo(String repo) {
		this.repo = repo;
	}

	public String getPrid() {
		return prid;
	}

	public void setPrid(String prid) {
		this.prid = prid;
	}

	/**
	 * From this object, create the skeleton of a PullRequest object
	 * 
	 * @return a barebones {@linkplain PullRequest} with the contents of this class
	 */
	public PullRequest createPR() {
		PullRequest pr = new PullRequest(getApiLabel());
		pr.setRepoName(getRepo());
		pr.setPrId(getPrid());
		return pr;
	}

}
