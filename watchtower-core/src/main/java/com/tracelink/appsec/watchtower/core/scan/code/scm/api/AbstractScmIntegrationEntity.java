package com.tracelink.appsec.watchtower.core.scan.code.scm.api;

import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;

/**
 * Entity description for an SCM Integration Entity
 *
 * @author csmith
 */
public abstract class AbstractScmIntegrationEntity extends ApiIntegrationEntity {

	@Override
	public ScanType getScanType() {
		return CodeScanType.PULL_REQUEST;
	}

	/**
	 * Create an HTTP link to view the Pull Request for the given repository and pullRequestId
	 *
	 * @param repository    the repository id
	 * @param pullRequestId the PR id
	 * @return an http link for this Pull Request, or null, if none could be made
	 */
	public abstract String makePRLink(String repository, String pullRequestId);

	/**
	 * Create an HTTP link to view a file at a commit in the SCM, at a line if given
	 *
	 * @param repository the repository name
	 * @param commitHash the commit
	 * @param filePath   the path relative to the repository root
	 * @param line       the line to show, 0 for none
	 * @return an http link to the file, or null, if none could be made
	 */
	public abstract String makeFileLink(String repository, String commitHash, String filePath,
			int line);

	public String getEndpointLink() {
		return "/rest/scan/" + getApiLabel();
	}
}
