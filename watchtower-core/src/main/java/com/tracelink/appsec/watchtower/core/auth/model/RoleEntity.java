package com.tracelink.appsec.watchtower.core.auth.model;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

/**
 * Entity description for the Role entity. Holds information about the Role name
 *
 * @author csmith
 */
@Entity
@Table(name = "roles")
public class RoleEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "role_id")
	private long id;

	@Column(name = "name")
	private String roleName;

	@Column(name = "description")
	private String description;

	@Column(name = "default_role")
	private boolean defaultRole;

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "role_privilege", joinColumns = @JoinColumn(name = "role_id"),
			inverseJoinColumns = @JoinColumn(name = "privilege_id"))
	private Set<PrivilegeEntity> privileges = new HashSet<>();

	public long getId() {
		return id;
	}

	public RoleEntity setId(long id) {
		this.id = id;
		return this;
	}

	public String getRoleName() {
		return roleName;
	}

	public RoleEntity setRoleName(String roleName) {
		this.roleName = roleName;
		return this;
	}

	public String getDescription() {
		return description;
	}

	public RoleEntity setDescription(String description) {
		this.description = description;
		return this;
	}

	public boolean isDefaultRole() {
		return defaultRole;
	}

	public RoleEntity setDefaultRole(boolean defaultRole) {
		this.defaultRole = defaultRole;
		return this;
	}

	public Set<PrivilegeEntity> getPrivileges() {
		return privileges;
	}

	public RoleEntity setPrivileges(Set<PrivilegeEntity> privileges) {
		this.privileges = privileges;
		return this;
	}


}
