package com.tracelink.appsec.watchtower.core.alerting.entity;

import com.tracelink.appsec.watchtower.core.encryption.converter.AlertWebhookEncryptedConverter;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Somewhere alerts are sent - today a Google Chat space's incoming webhook. The URL is a
 * credential: encrypted at rest and never returned to the browser.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "alert_channels")
public class AlertChannelEntity {

	/** The only channel type so far. */
	public static final String GOOGLE_CHAT = "GOOGLE_CHAT";

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "channel_id")
	private long id;

	@Column(name = "name")
	private String name;

	@Column(name = "channel_type")
	private String type = GOOGLE_CHAT;

	@Column(name = "webhook_url")
	@Convert(converter = AlertWebhookEncryptedConverter.class)
	private String webhookUrl;

	@Column(name = "enabled")
	private boolean enabled = true;

	@Column(name = "created_by")
	private String createdBy;

	@Column(name = "updated_by")
	private String updatedBy;

	@Column(name = "updated_at")
	private long updatedAt;

	@Column(name = "last_test_at")
	private Long lastTestAt;

	@Column(name = "last_test_status")
	private String lastTestStatus;

	public long getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getWebhookUrl() {
		return webhookUrl;
	}

	public void setWebhookUrl(String webhookUrl) {
		this.webhookUrl = webhookUrl;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getCreatedBy() {
		return createdBy;
	}

	public void setCreatedBy(String createdBy) {
		this.createdBy = createdBy;
	}

	public String getUpdatedBy() {
		return updatedBy;
	}

	public void setUpdatedBy(String updatedBy) {
		this.updatedBy = updatedBy;
	}

	public long getUpdatedAt() {
		return updatedAt;
	}

	public void setUpdatedAt(long updatedAt) {
		this.updatedAt = updatedAt;
	}

	public Long getLastTestAt() {
		return lastTestAt;
	}

	public void setLastTestAt(Long lastTestAt) {
		this.lastTestAt = lastTestAt;
	}

	public String getLastTestStatus() {
		return lastTestStatus;
	}

	public void setLastTestStatus(String lastTestStatus) {
		this.lastTestStatus = lastTestStatus;
	}
}
