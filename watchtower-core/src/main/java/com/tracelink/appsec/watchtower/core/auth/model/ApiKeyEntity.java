package com.tracelink.appsec.watchtower.core.auth.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Transient;

/**
 * Entity definition for API keys. Maps back to a single user
 *
 * @author csmith
 */
@Entity
@Table(name = "api_keys")
public class ApiKeyEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "api_key_id")
	private int id;

	@Column(name = "label")
	private String keyLabel;

	@Column(name = "api_key")
	private String apiKeyId;

	@Column(name = "secret")
	private String secret;

	@Transient
	private String firstTimeSecret;

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "user_id")
	private UserEntity user;

	public String getKeyLabel() {
		return keyLabel;
	}

	public void setKeyLabel(String keyLabel) {
		this.keyLabel = keyLabel;
	}

	public String getApiKeyId() {
		return apiKeyId;
	}

	public void setApiKeyId(String apiKey) {
		this.apiKeyId = apiKey;
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	/**
	 * First Time Secret is only set during key creation. After save, this secret value is not set.
	 *
	 * @return the plaintext secret (only accessible during create)
	 */
	public String getFirstTimeSecret() {
		return firstTimeSecret;
	}

	public void setFirstTimeSecret(String firstTimeSecret) {
		this.firstTimeSecret = firstTimeSecret;
	}

	public UserEntity getUser() {
		return user;
	}

	public void setUser(UserEntity user) {
		this.user = user;
	}
}
