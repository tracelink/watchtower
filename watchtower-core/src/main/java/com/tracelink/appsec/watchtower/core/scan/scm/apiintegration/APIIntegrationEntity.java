package com.tracelink.appsec.watchtower.core.scan.scm.apiintegration;

import java.util.Map;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.scm.ApiType;

/**
 * Entity description for the abstract API entity inherited object. Holds information about the api
 * label and defers all other information to implementations
 *
 * @author csmith
 */
@Entity
@Table(name = "integration_entity")
@Inheritance(strategy = InheritanceType.JOINED)
public abstract class APIIntegrationEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "integration_id")
	private long integrationId;

	@Column(name = "api_label")
	private String apiLabel;

	@Column(name = "api_endpoint")
	private String apiEndpoint;

	public long getIntegrationId() {
		return integrationId;
	}

	public void setIntegrationId(long integrationId) {
		this.integrationId = integrationId;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getApiEndpoint() {
		return apiEndpoint;
	}

	public void setApiEndpoint(String apiEndpoint) {
		this.apiEndpoint = apiEndpoint.toLowerCase();
	}

	public String getEndpointLink() {
		return String.format("/rest/scan/%s", getApiEndpoint());
	}

	/**
	 * Get the {@linkplain ApiType} for this Integration Entity
	 * 
	 * @return the {@linkplain ApiType}
	 */
	public abstract ApiType getApiType();

	/**
	 * Given a set of parameters from an HTTP request, populate the settings for this object
	 * 
	 * @param parameters the map of parameters to use to populate this object
	 * @throws ApiIntegrationException if the parameters are wrong or incomplete
	 */
	public abstract void configureEntityFromParameters(Map<String, String> parameters)
			throws ApiIntegrationException;

	/**
	 * Create an HTTP link to view the Pull Request for the given repository and pullRequestId
	 * 
	 * @param repository    the repository id
	 * @param pullRequestId the PR id
	 * @return an http link for this Pull Request, or null, if none could be made
	 */
	public abstract String makePRLink(String repository, String pullRequestId);
}
