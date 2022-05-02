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

	public String getEndpointLink() {
		return "/rest/scan/" + getApiLabel();
	}
}
