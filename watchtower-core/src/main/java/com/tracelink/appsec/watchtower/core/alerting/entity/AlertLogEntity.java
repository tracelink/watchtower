package com.tracelink.appsec.watchtower.core.alerting.entity;

import com.tracelink.appsec.watchtower.core.alerting.AlertStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One alert message queued for, or sent to, a channel. The delivery worker drains it; Alert
 * Settings shows the most recent ones.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "alert_log")
public class AlertLogEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "log_id")
	private long id;

	@Column(name = "alert_type")
	private String alertType;

	@Column(name = "route_id")
	private long routeId;

	@Column(name = "channel_id")
	private long channelId;

	@Column(name = "thread_key")
	private String threadKey;

	@Column(name = "status")
	@Enumerated(EnumType.STRING)
	private AlertStatus status = AlertStatus.PENDING;

	@Column(name = "attempts")
	private int attempts;

	@Column(name = "next_attempt_at")
	private long nextAttemptAt;

	@Column(name = "sent_at")
	private Long sentAt;

	@Column(name = "created_at")
	private long createdAt;

	/** Why the last attempt failed; never includes the webhook URL. */
	@Column(name = "last_error")
	private String lastError;

	/** The message text. Built from findings metadata only - never a secret. */
	@Column(name = "payload")
	private String payload;

	public long getId() {
		return id;
	}

	public String getAlertType() {
		return alertType;
	}

	public void setAlertType(String alertType) {
		this.alertType = alertType;
	}

	public long getRouteId() {
		return routeId;
	}

	public void setRouteId(long routeId) {
		this.routeId = routeId;
	}

	public long getChannelId() {
		return channelId;
	}

	public void setChannelId(long channelId) {
		this.channelId = channelId;
	}

	public String getThreadKey() {
		return threadKey;
	}

	public void setThreadKey(String threadKey) {
		this.threadKey = threadKey;
	}

	public AlertStatus getStatus() {
		return status;
	}

	public void setStatus(AlertStatus status) {
		this.status = status;
	}

	public int getAttempts() {
		return attempts;
	}

	public void setAttempts(int attempts) {
		this.attempts = attempts;
	}

	public long getNextAttemptAt() {
		return nextAttemptAt;
	}

	public void setNextAttemptAt(long nextAttemptAt) {
		this.nextAttemptAt = nextAttemptAt;
	}

	public Long getSentAt() {
		return sentAt;
	}

	public void setSentAt(Long sentAt) {
		this.sentAt = sentAt;
	}

	public long getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(long createdAt) {
		this.createdAt = createdAt;
	}

	public String getLastError() {
		return lastError;
	}

	public void setLastError(String lastError) {
		this.lastError = lastError;
	}

	public String getPayload() {
		return payload;
	}

	public void setPayload(String payload) {
		this.payload = payload;
	}
}
