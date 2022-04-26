package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import java.util.Map;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.Table;

/**
 * Entity description for the abstract API entity inherited object. Holds information about the api
 * label and defers all other information to implementations
 *
 * @author csmith
 */
@Entity
@Table(name = "integration_entity")
@Inheritance(strategy = InheritanceType.JOINED)
public abstract class ApiIntegrationEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "integration_id")
	private long integrationId;

	@Column(name = "api_label")
	private String apiLabel;

	@Column(name = "register_state")
	@Enumerated(value = EnumType.STRING)
	private RegisterState registerState = RegisterState.NOT_SUPPORTED;

	@Column(name = "register_error")
	private String registerError;

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

	public RegisterState getRegisterState() {
		return registerState;
	}

	public void setRegisterState(RegisterState registerState) {
		this.registerState = registerState;
	}

	public String getRegisterError() {
		return registerError;
	}

	public void setRegisterError(String registerError) {
		this.registerError = registerError;
	}

	/**
	 * Get the {@linkplain ApiType} for this Integration Entity
	 *
	 * @return the {@linkplain ApiType}
	 */
	public abstract ApiType getApiType();

	/**
	 * Get the {@linkplain ScanType} for this Integration Entity
	 *
	 * @return the {@linkplain ScanType}
	 */
	public abstract ScanType getScanType();

	/**
	 * Given a set of parameters from an HTTP request, populate the settings for this object
	 *
	 * @param parameters the map of parameters to use to populate this object
	 * @throws ApiIntegrationException if the parameters are wrong or incomplete
	 */
	public abstract void configureEntityFromParameters(Map<String, String> parameters)
			throws ApiIntegrationException;

	/**
	 * Create the corresponding API client for this api entity
	 *
	 * @return an appropriate {@linkplain IWatchtowerApi} for this label
	 */
	public abstract IWatchtowerApi createApi();

	public abstract String getEndpointLink();

}
