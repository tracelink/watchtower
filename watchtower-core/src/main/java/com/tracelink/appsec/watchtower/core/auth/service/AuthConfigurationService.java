package com.tracelink.appsec.watchtower.core.auth.service;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.module.ModuleException;

/**
 * Service to manage new privileges from Modules and ensure that all default authentication and
 * authorization is setup correctly in Watchtower so that users cannot get locked out.
 * 
 * @author csmith
 *
 */
@Service
public class AuthConfigurationService {

	private UserService userService;

	private RoleService roleService;

	private PrivilegeService privService;

	public AuthConfigurationService(@Autowired UserService userService,
			@Autowired RoleService roleService,
			@Autowired PrivilegeService privService) {
		this.userService = userService;
		this.roleService = roleService;
		this.privService = privService;
	}

	/**
	 * register a new privilege in Watchtower and assign it to the Admin role
	 * 
	 * @param moduleName           the name of the owning module
	 * @param category             the logical category to add this privilege under (for UI)
	 * @param privilegeName        the name of the privilege to add
	 * @param privilegeDescription the description of the privilege
	 * @throws ModuleException If the privilege name is already used
	 */
	public void registerNewPrivilege(String moduleName, String category, String privilegeName,
			String privilegeDescription) throws ModuleException {
		PrivilegeEntity priv = privService.findByName(privilegeName);
		PrivilegeEntity newPriv = new PrivilegeEntity().setName(privilegeName).setModule(moduleName)
				.setCategory(category).setDescription(privilegeDescription);
		if (priv != null && !priv.equals(newPriv)) {
			throw new ModuleException(
					"Cannot register privilege: " + privilegeName
							+ ". That name already exists in a different module.");
		}
		newPriv = privService.upsertPrivilege(newPriv);
		RoleEntity adminRole = roleService.findRoleByName(RoleService.DEFAULT_ADMIN_ROLE);
		adminRole.getPrivileges().add(newPriv);
		roleService.saveRole(adminRole);
	}

	@PostConstruct
	public void setupDefaultAuth() {
		privService.ensureDefaultPrivileges();
		roleService.ensureDefaultRoles(privService.getAllPrivileges());
		userService.ensureDefaultUsers(roleService.findRoleByName(RoleService.DEFAULT_ADMIN_ROLE));
	}
}
