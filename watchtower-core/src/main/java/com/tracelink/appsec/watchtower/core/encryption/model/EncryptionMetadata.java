package com.tracelink.appsec.watchtower.core.encryption.model;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Model for Watchtower encryption metadata. Includes the date and time of the last key encryption
 * key rotation, as well as whether auto-rotation of data encryption keys is enabled and the period
 * (in days) between rotations.
 *
 * @author mcool
 */
@Entity
@Table(name = "encryption_metadata")
public class EncryptionMetadata {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "metadata_id")
	private Long id;

	@Column(name = "last_rotation_date_time")
	private LocalDateTime lastRotationDateTime;

	@Column(name = "rotation_schedule_enabled")
	private boolean rotationScheduleEnabled = false;

	@Column(name = "rotation_period")
	private Integer rotationPeriod = null;

	public Long getId() {
		return id;
	}

	public LocalDateTime getLastRotationDateTime() {
		return lastRotationDateTime;
	}

	public void setLastRotationDateTime(LocalDateTime lastRotationDateTime) {
		this.lastRotationDateTime = lastRotationDateTime;
	}

	public long getLastRotationDateTimeMillis() {
		return lastRotationDateTime == null ? 0L
				: lastRotationDateTime.toInstant(ZoneOffset.UTC).toEpochMilli();
	}

	public boolean isRotationScheduleEnabled() {
		return rotationScheduleEnabled;
	}

	public void setRotationScheduleEnabled(boolean rotationScheduleEnabled) {
		this.rotationScheduleEnabled = rotationScheduleEnabled;
	}

	public Integer getRotationPeriod() {
		return rotationPeriod;
	}

	public void setRotationPeriod(Integer rotationPeriod) {
		this.rotationPeriod = rotationPeriod;
	}
}
