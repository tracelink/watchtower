package com.tracelink.appsec.module.pmd.model;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Entity description for a PMD rule property. Used for both PMD XPath and PMD
 * Java rules.
 *
 * @author mcool
 */
@Entity
@Table(name = "pmd_properties")
public class PMDPropertyEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "property_id")
	private long id;

	@Column(name = "property_name")
	private String name;

	@Column(name = "property_value")
	private String value;

	public long getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getValue() {
		return decodeField(value);
	}

	public void setValue(String value) {
		this.value = encodeField(value);
	}

	/**
	 * Converts this PMD property database entity object into a data transfer
	 * object. Used for PMD ruleset export and for editing rules.
	 *
	 * @return the PMD property DTO represented by this database object
	 */
	public PMDPropertyDto toDto() {
		PMDPropertyDto dto = new PMDPropertyDto();
		dto.setId(getId());
		dto.setName(getName());
		dto.setValue(getValue());
		return dto;
	}

	private static String decodeField(String field) {
		String decodedField;
		try {
			decodedField = new String(Hex.decodeHex(field), StandardCharsets.UTF_8);
		} catch (DecoderException e) {
			decodedField = "";
		}
		return decodedField;
	}

	private static String encodeField(String field) {
		return Hex.encodeHexString(field.getBytes());
	}
}
