package com.tracelink.appsec.module.eslint.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Entity description for a ESLint rule message. Used for both ESLint core and ESLint custom rules.
 *
 * @author mcool
 */
@Entity
@Table(name = "eslint_messages")
public class EsLintMessageEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "message_id")
	private long id;

	@Column(name = "message_key")
	private String key;

	@Column(name = "message_value")
	private String value;

	public long getId() {
		return id;
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
	 * Converts this ESLint message database entity object into a data transfer object. Used for
	 * ESLint ruleset export and for editing rules.
	 *
	 * @return the ESLint message DTO represented by this database object
	 */
	public EsLintMessageDto toDto() {
		EsLintMessageDto dto = new EsLintMessageDto();
		dto.setId(getId());
		dto.setKey(getKey());
		dto.setValue(getValue());
		return dto;
	}
}
