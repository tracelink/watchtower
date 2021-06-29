package com.tracelink.appsec.watchtower.core.encryption.model;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.encryption.converter.DataEncryptionKeyConverter;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity.HexStringConverter;

/**
 * Model for the Watchtower data encryption key. Includes the name of the encrypted attribute
 * converter class, which is unique, along with the current and previous encryption keys, the date
 * and time of the last key rotation, and whether the key rotation is currently in progress.
 *
 * @author mcool
 */
@Entity
@Table(name = "data_encryption_keys")
public class DataEncryptionKey {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "key_id")
	private Long id;

	@Column(name = "converter_class_name")
	@Convert(converter = HexStringConverter.class)
	private String converterClassName;

	@Column(name = "current_key")
	@Convert(converter = DataEncryptionKeyConverter.class)
	private Key currentKey;

	@Column(name = "previous_key")
	@Convert(converter = DataEncryptionKeyConverter.class)
	private Key previousKey;

	@Column(name = "last_rotation_date_time")
	private LocalDateTime lastRotationDateTime;

	@Column(name = "rotation_in_progress")
	private boolean rotationInProgress = false;

	@Column(name = "disabled")
	private boolean disabled = false;

	public Long getId() {
		return id;
	}

	public String getConverterClassName() {
		return converterClassName;
	}

	public void setConverterClassName(String converterClassName) {
		this.converterClassName = converterClassName;
	}

	public Key getCurrentKey() {
		return currentKey;
	}

	public void setCurrentKey(Key currentKey) {
		this.currentKey = currentKey;
	}

	public Key getPreviousKey() {
		return previousKey;
	}

	public void setPreviousKey(Key previousKey) {
		this.previousKey = previousKey;
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

	public boolean isRotationInProgress() {
		return rotationInProgress;
	}

	public void setRotationInProgress(boolean rotationInProgress) {
		this.rotationInProgress = rotationInProgress;
	}

	/**
	 * Tells whether this data encryption key is disabled. A key is disabled if Watchtower is
	 * configured with {@code decryptMode} and all data in the database has been decrypted.
	 *
	 * @return true if the data encryption key is disabled, false otherwise
	 */
	public boolean isDisabled() {
		return disabled;
	}

	public void setDisabled(boolean disabled) {
		this.disabled = disabled;
	}
}
