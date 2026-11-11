package com.tracelink.appsec.watchtower.core.auth.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.apache.commons.codec.binary.StringUtils;

/**
 * Entity description for a privilege
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "privileges")
public class PrivilegeEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "privilege_id")
	private long id;

	@Column(name = "name")
	private String name;

	@Column(name = "description")
	private String description;

	@Column(name = "module")
	private String module;

	@Column(name = "category")
	private String category;

	public long getId() {
		return id;
	}

	public PrivilegeEntity setId(long id) {
		this.id = id;
		return this;
	}

	public String getName() {
		return name;
	}

	public PrivilegeEntity setName(String name) {
		this.name = name;
		return this;
	}

	public String getDescription() {
		return description;
	}

	public PrivilegeEntity setDescription(String description) {
		this.description = description;
		return this;
	}

	public String getModule() {
		return module;
	}

	public PrivilegeEntity setModule(String module) {
		this.module = module;
		return this;
	}

	public String getCategory() {
		return category;
	}

	public PrivilegeEntity setCategory(String category) {
		this.category = category;
		return this;
	}

	@Override
	public boolean equals(Object other) {
		if (other == this) {
			return true;
		}
		if (!(other instanceof PrivilegeEntity)) {
			return false;
		}
		PrivilegeEntity otherPriv = (PrivilegeEntity) other;
		return StringUtils.equals(getName(), otherPriv.getName()) &&
				StringUtils.equals(getCategory(), otherPriv.getCategory()) &&
				StringUtils.equals(getDescription(), otherPriv.getDescription());
	}

	@Override
	public int hashCode() {
		return (category + name).hashCode();
	}
}
