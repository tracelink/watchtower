package com.tracelink.appsec.module.pmd.model;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * Represents a data transfer object for the {@link PMDPropertyEntity}. All fields in this object
 * are in plain text.
 *
 * @author mcool
 */
public class PMDPropertyDto {
	private Long id;

	@NotNull(message = "Property name cannot be null.")
	@NotEmpty(message = "Property name cannot be empty.")
	@Size(max = 255, message = "Property name cannot have a length of more than 256 characters.")
	private String name;

	@NotNull(message = "Property value cannot be null.")
	@NotEmpty(message = "Property value cannot be empty.")
	private String value;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	/**
	 * Converts this PMD property data transfer object into a database entity object. Used for PMD
	 * ruleset import.
	 *
	 * @return the PMD property database object represented by this DTO
	 */
	public PMDPropertyEntity toEntity() {
		PMDPropertyEntity property = new PMDPropertyEntity();
		property.setName(getName());
		property.setValue(getValue());
		return property;
	}
}
