package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import java.util.Map;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.InheritanceType;
import jakarta.persistence.Table;

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

	@Column(name = "watchtower_secret")
	private String watchtowerSecret;

	/** When the connection was last checked (test button, catalog sync, the 6-hourly check). */
	@Column(name = "health_checked_at")
	private Long healthCheckedAt;

	@Column(name = "health_ok")
	private Boolean healthOk;

	/** Why the last check failed: truncated, credentials stripped. */
	@Column(name = "health_error")
	private String healthError;

	public Long getHealthCheckedAt() {
		return healthCheckedAt;
	}

	public Boolean getHealthOk() {
		return healthOk;
	}

	public String getHealthError() {
		return healthError;
	}

	/** Sets the last connection check; IntegrationHealthService records it in the database. */
	public void setHealth(Long checkedAt, Boolean ok, String error) {
		this.healthCheckedAt = checkedAt;
		this.healthOk = ok;
		this.healthError = error;
	}

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

	public String getWatchtowerSecret() {
		return watchtowerSecret;
	}

	public void setWatchtowerSecret(String watchtowerSecret) {
		this.watchtowerSecret = watchtowerSecret;
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
	 * Adds already-configured secret values to an update request when their input fields were
	 * intentionally left blank. Implementations must only copy secret values and must never expose
	 * them to a view model.
	 *
	 * @param parameters mutable request parameters for the update
	 */
	public void preserveConfiguredSecrets(Map<String, String> parameters) {
		// Most integration types do not define additional credentials.
	}

	/**
	 * Create the corresponding API client for this api entity
	 *
	 * @return an appropriate {@linkplain IWatchtowerApi} for this label
	 */
	public abstract IWatchtowerApi createApi();

	public abstract String getEndpointLink();

}
