package com.tracelink.appsec.watchtower.core.scan.scm.bb;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Table;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.encryption.converter.StringEncryptedAttributeConverter;
import com.tracelink.appsec.watchtower.core.scan.scm.ApiType;
import com.tracelink.appsec.watchtower.core.scan.scm.apiintegration.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.apiintegration.ApiIntegrationException;

/**
 * Entity for the Bitbucket Cloud Integration API
 *
 * @author csmith
 *
 */
@Entity
@Table(name = "bb_cloud_integration_entity")
public class BBCloudIntegrationEntity extends APIIntegrationEntity {

	@Column(name = "workspace")
	private String workspace;

	@Column(name = "username")
	private String user;

	@Column(name = "authentication")
	@Convert(converter = StringEncryptedAttributeConverter.class)
	private String auth;

	public String getWorkspace() {
		return workspace;
	}

	public void setWorkspace(String workspace) {
		this.workspace = workspace;
	}

	public String getApiBase() {
		return "https://api.bitbucket.org/2.0";
	}

	/**
	 * Make the workspace url for the Bitbucket cloud API
	 *
	 * @return the api workspace url
	 */
	public String makeApiWorkspaceUrl() {
		return String.format("%s/repositories/%s", getApiBase(), getWorkspace());
	}

	/**
	 * Make the repository url for the Bitbucket cloud API
	 *
	 * @param repositoryName the repository to use
	 * @return the api repository url
	 */
	public String makeApiRepoUrl(String repositoryName) {
		return String.format("%s/repositories/%s/%s", getApiBase(), getWorkspace(),
				repositoryName);
	}

	/**
	 * Make the pull request url for the Bitbucket cloud API
	 *
	 * @param repositoryName the repository to use
	 * @param pullRequestId  the pull request to use
	 * @return the api pull request url
	 */
	public String makeApiPRUrl(String repositoryName, String pullRequestId) {
		return String.format("%s/pullrequests/%s", makeApiRepoUrl(repositoryName), pullRequestId);
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getAuth() {
		return auth;
	}

	public void setAuth(String auth) {
		this.auth = auth;
	}

	@Override
	public void configureEntityFromParameters(Map<String, String> parameters)
			throws ApiIntegrationException {
		List<String> neededParams =
				new ArrayList<>(Arrays.asList("apiLabel", "workspace", "user", "auth"));
		parameters.entrySet().removeIf(e -> StringUtils.isBlank(e.getValue()));
		neededParams.removeAll(parameters.keySet());

		if (!neededParams.isEmpty()) {
			throw new ApiIntegrationException("Missing value for "
					+ neededParams.stream().collect(Collectors.joining(", ")));
		}
		String apiLabel = parameters.get("apiLabel");
		setApiLabel(apiLabel);
		setApiEndpoint(apiLabel);
		setWorkspace(parameters.get("workspace"));
		setUser(parameters.get("user"));
		setAuth(parameters.get("auth"));
	}

	@Override
	public String makePRLink(String repository, String pullRequestId) {
		return String.format("https://bitbucket.org/%s/%s/pull-requests/%s", getWorkspace(),
				repository, pullRequestId);
	}

	/**
	 * Create a link to download the zip source of a repo at a commit
	 * 
	 * @param repository the repository of the code
	 * @param commitId   the commit hash to download at
	 * @return a download link
	 */
	public String makeDownloadLink(String repository, String commitId) {
		return String.format("https://bitbucket.org/%s/%s/get/%s.zip", getWorkspace(), repository,
				commitId);
	}

	@Override
	public ApiType getApiType() {
		return ApiType.BITBUCKET_CLOUD;
	}
}
