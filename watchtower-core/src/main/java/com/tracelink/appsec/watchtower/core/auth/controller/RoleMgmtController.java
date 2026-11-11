package com.tracelink.appsec.watchtower.core.auth.controller;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.ConversionService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.service.PrivilegeService;
import com.tracelink.appsec.watchtower.core.auth.service.RoleService;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;

/**
 * Controller for all Role Management including showing current role's permissions, editing and
 * deleting roles, and assigning a role as default
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.ROLE_VIEW_NAME + "')")
public class RoleMgmtController {

	private RoleService roleService;

	private ConversionService conversionService;

	private PrivilegeService privilegeService;

	private UserService userService;

	public RoleMgmtController(@Autowired RoleService roleService,
			@Autowired ConversionService conversionService,
			@Autowired PrivilegeService privilegeService,
			@Autowired UserService userService) {
		this.roleService = roleService;
		this.conversionService = conversionService;
		this.privilegeService = privilegeService;
		this.userService = userService;
	}

	@GetMapping("/rolemgmt")
	public WatchtowerModelAndView rolemgmt(@RequestParam(defaultValue = "0") int page) {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("admin/rolemgmt");
		if (page < 0) {
			mv.setViewName("redirect:/rolemgmt?page=0");
			return mv;
		}
		PageRequest pageable = PageRequest.of(page, 10, Sort.by("roleName"));
		Page<RoleEntity> roles = roleService.findRoles(pageable);
		List<RoleEntity> allRoles = roleService.findAllRoles();
		if (roles == null) roles = new PageImpl<>(allRoles, pageable, allRoles.size());
		PagedResult<RoleEntity> pagination = PagedResult.of(roles, role -> role);
		if (pagination.totalPages() > 0 && page >= pagination.totalPages()) {
			mv.setViewName("redirect:/rolemgmt?page=" + (pagination.totalPages() - 1));
			return mv;
		}
		mv.addObject("roles", pagination.content());
		mv.addObject("allRoles", allRoles);
		mv.addObject("pagination", pagination);
		mv.addObject("defaultRole", roleService.findDefaultRole());
		// Users per role and the privilege total for the "9 of 54" meter (UAT walkthrough).
		mv.addObject("roleUsers", userService.countUsersByRole());
		mv.addObject("privilegeTotal", privilegeService.getAllPrivileges().size());
		mv.addScriptReference("/scripts/rolemgmt.js");
		return mv;
	}

	@GetMapping("/rolemgmt/edit/{id}")
	public WatchtowerModelAndView editRole(@PathVariable long id,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView modelAndView = new WatchtowerModelAndView("admin/roleedit");
		RoleEntity role = roleService.findRoleById(id);

		if (role == null) {
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
							"Cannot find role.");
			modelAndView.setViewName("redirect:/rolemgmt");
		} else {
			List<PrivilegeEntity> privileges = privilegeService.getAllPrivileges();
			Map<String, List<PrivilegeEntity>> privilegesByModule = new LinkedHashMap<>();
			for (PrivilegeEntity privilege : privileges) {
				String module = StringUtils.defaultIfBlank(privilege.getModule(), "Other");
				privilegesByModule.computeIfAbsent(module, ignored -> new java.util.ArrayList<>())
						.add(privilege);
			}
			modelAndView.addObject("role", role);
			modelAndView.addObject("privileges", privileges);
			modelAndView.addObject("privilegesByModule", privilegesByModule);
			modelAndView.addScriptReference("/scripts/role-privileges.js");
		}
		return modelAndView;
	}

	@PostMapping("/rolemgmt/edit")
	@PreAuthorize("hasAuthority('" + CorePrivilege.ROLE_MODIFY_NAME + "')")
	public String saveRole(@RequestParam int id, @RequestParam Map<String, String> parameters,
			RedirectAttributes redirectAttributes) {
		RoleEntity role = roleService.findRoleById(id);
		// Make sure role exists
		if (role == null) {
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
							"Cannot find role.");
		} else if (roleService.isBuiltInRole(role)) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit a built in role");
		} else {
			Set<PrivilegeEntity> privs = new HashSet<>();
			for (String param : parameters.keySet()) {
				PrivilegeEntity desiredPriv = privilegeService.findByName(param);
				if (desiredPriv == null) {
					// this is fine
					continue;
				}
				Boolean desiredState = conversionService
						.convert(parameters.get(param), Boolean.class);
				// Update privs if the user doesn't have the priv but should
				if (desiredState != null && desiredState) {
					privs.add(desiredPriv);
				}
			}

			role.setPrivileges(privs);

			roleService.saveRole(role);

			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Role information for " + role.getRoleName() + " saved successfully.");
		}
		return "redirect:/rolemgmt";
	}

	@PostMapping("/rolemgmt/delete")
	@PreAuthorize("hasAuthority('" + CorePrivilege.ROLE_MODIFY_NAME + "')")
	public String deleteRole(@RequestParam int id, RedirectAttributes redirectAttributes) {
		RoleEntity role = roleService.findRoleById(id);

		if (role == null) {
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
							"Cannot delete role.");
		} else if (roleService.isBuiltInRole(role)) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot delete a built in role");
		} else if (role.isDefaultRole()) {
			// The page shows "In use" instead of Delete for the default role.
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"The default role can't be deleted. Make another role the default first.");
		} else {
			roleService.deleteRole(role);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Role " + role.getRoleName() + " deleted successfully");
		}
		return "redirect:/rolemgmt";
	}

	@PostMapping("/rolemgmt/create")
	@PreAuthorize("hasAuthority('" + CorePrivilege.ROLE_MODIFY_NAME + "')")
	public String createRole(@RequestParam String roleName, @RequestParam String roleDescription,
			RedirectAttributes redirectAttributes) {
		String redirect = "redirect:/rolemgmt";
		if (StringUtils.isBlank(roleName)) {
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
							"Role must have a name.");
		} else if (roleService.findRoleByName(roleName) != null) {
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
							"Role already exists.");
		} else {
			RoleEntity newRole = new RoleEntity();
			newRole.setRoleName(roleName);
			newRole.setDescription(roleDescription);
			newRole = roleService.upsertRole(newRole);

			redirect = "redirect:/rolemgmt/edit/" + newRole.getId();
		}
		return redirect;
	}

	@PostMapping("/rolemgmt/default")
	@PreAuthorize("hasAuthority('" + CorePrivilege.ROLE_MODIFY_NAME + "')")
	public String setDefaultRole(@RequestParam long roleId,
			RedirectAttributes redirectAttributes) {
		if (roleId == -1) {
			roleService.unassignDefaultRoles();
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully unassigned default role for new users");
		} else {
			RoleEntity role = roleService.findRoleById(roleId);
			if (role == null) {
				redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"Cannot assign default role. Unknown Id");
			} else {
				roleService.assignDefaultRole(role);
				redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully assigned " + role.getRoleName()
								+ " as the default role for new users");
			}
		}
		return "redirect:/rolemgmt";
	}
}
