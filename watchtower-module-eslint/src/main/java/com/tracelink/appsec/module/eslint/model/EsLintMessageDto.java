package com.tracelink.appsec.module.eslint.model;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * Represents a data transfer object for the {@link EsLintMessageEntity}.
 *
 * @author mcool
 */
public class EsLintMessageDto {

	private long id;

	@NotNull(message = "Message key cannot be null.")
	@NotEmpty(message = "Message key cannot be empty.")
	@Size(max = 255, message = "Message key cannot have a length of more than 256 characters.")
	private String key;

	@NotNull(message = "Message value cannot be null.")
	@NotEmpty(message = "Message value cannot be empty.")
	@Size(max = 255, message = "Message value cannot have a length of more than 256 characters.")
	private String value;

	/**
	 * Default constructor
	 */
	public EsLintMessageDto() {

	}

	/**
	 * Convenience constructor to set key and value in one line.
	 *
	 * @param key   the key of the message
	 * @param value the value of the message
	 */
	public EsLintMessageDto(String key, String value) {
		this.key = key;
		this.value = value;
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	/**
	 * Converts this ESLint message data transfer object into a database entity object. Used for
	 * ESLint ruleset import.
	 *
	 * @return the ESLint message database object represented by this DTO
	 */
	public EsLintMessageEntity toEntity() {
		EsLintMessageEntity message = new EsLintMessageEntity();
		message.setKey(getKey());
		message.setValue(getValue());
		return message;
	}
}
