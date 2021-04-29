package com.tracelink.appsec.watchtower.core.auth.service;

import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.repository.RoleRepository;

/**
 * Service that manages roles and assigning one as the "default" role for all new users
 * 
 * @author csmith
 *
 */
@Service
public class RoleService {
	public static final String DEFAULT_ADMIN_ROLE = "Full System Admin";

	private RoleRepository roleRepository;

	public RoleService(@Autowired RoleRepository roleRepository) {
		this.roleRepository = roleRepository;
	}

	/**
	 * Guarantee that the default admin role is in place in Watchtower and contains all known
	 * privileges
	 * 
	 * @param allPrivs the collection of all privileges to add to the admin role
	 */
	void ensureDefaultRoles(Collection<PrivilegeEntity> allPrivs) {
		RoleEntity adminRole = new RoleEntity().setRoleName(DEFAULT_ADMIN_ROLE)
				.setDescription("The default Role for full system admin control");
		adminRole.getPrivileges().addAll(allPrivs);
		upsertRole(adminRole);
	}

	/**
	 * If a default role is assigned, unassign it.
	 */
	public void unassignDefaultRoles() {
		RoleEntity defaultRole = roleRepository.findByDefaultRoleTrue();
		if (defaultRole != null) {
			defaultRole.setDefaultRole(false);
			saveRole(defaultRole);
		}
	}

	/**
	 * Unassign any existing role marked default and the set the given role as default
	 * 
	 * @param newDefaultRole the new default role
	 * @return the saved default role
	 */
	public RoleEntity assignDefaultRole(RoleEntity newDefaultRole) {
		unassignDefaultRoles();
		newDefaultRole.setDefaultRole(true);
		return upsertRole(newDefaultRole);
	}

	/**
	 * Find the default role in Watchtower
	 * 
	 * @return the default role or null if it doesn't exist
	 */
	public RoleEntity findDefaultRole() {
		return roleRepository.findByDefaultRoleTrue();
	}

	/**
	 * Get all roles in the system
	 * 
	 * @return all roles in the system
	 */
	public List<RoleEntity> findAllRoles() {
		return this.roleRepository.findAll();
	}

	/**
	 * Get a role by the given name, or null if not found
	 * 
	 * @param name the role name
	 * @return the role if found, else null
	 */
	public RoleEntity findRoleByName(String name) {
		return this.roleRepository.findByRoleName(name);
	}

	/**
	 * Get a role by the given id, or null if not found
	 * 
	 * @param id the role id
	 * @return the role if found, else null
	 */
	public RoleEntity findRoleById(long id) {
		return roleRepository.findById(id).orElse(null);
	}

	/**
	 * Update or insert the given role if another role by the same name already exists
	 * 
	 * @param entity the role to update/insert
	 * @return the saved role
	 */
	public RoleEntity upsertRole(RoleEntity entity) {
		RoleEntity oldEntity = roleRepository.findByRoleName(entity.getRoleName());
		if (oldEntity != null) {
			entity.setId(oldEntity.getId());
		}
		return roleRepository.saveAndFlush(entity);
	}

	/**
	 * Save a new role to the database
	 * 
	 * @param newRole the new role
	 * @return the saved version of the role
	 */
	public RoleEntity saveRole(RoleEntity newRole) {
		return roleRepository.saveAndFlush(newRole);
	}

	/**
	 * Remove the given role from the database
	 * 
	 * @param role the role to delete
	 */
	public void deleteRole(RoleEntity role) {
		roleRepository.delete(role);
	}

	/**
	 * true if the given role is managed by the system
	 * 
	 * @param role the role to test
	 * @return true if the role is owned by Watchtower, false otherwise
	 */
	public boolean isBuiltInRole(RoleEntity role) {
		return DEFAULT_ADMIN_ROLE.equals(role.getRoleName());
	}

}
