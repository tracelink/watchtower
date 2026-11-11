package com.tracelink.appsec.watchtower.core.alerting.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Records that a route has alerted on an item, so a repeated push does not alert again within
 * the route's dedupe window. Separate from {@link AlertLogEntity} because one message can carry
 * many items.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "alert_dedupe")
public class AlertDedupeEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "dedupe_id")
	private long id;

	@Column(name = "route_id")
	private long routeId;

	@Column(name = "dedupe_key")
	private String dedupeKey;

	@Column(name = "created_at")
	private long createdAt;

	public AlertDedupeEntity() {
	}

	public AlertDedupeEntity(long routeId, String dedupeKey, long createdAt) {
		this.routeId = routeId;
		this.dedupeKey = dedupeKey;
		this.createdAt = createdAt;
	}

	public long getId() {
		return id;
	}

	public long getRouteId() {
		return routeId;
	}

	public String getDedupeKey() {
		return dedupeKey;
	}

	public long getCreatedAt() {
		return createdAt;
	}
}
