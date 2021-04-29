package com.tracelink.appsec.watchtower.core.auth.controller;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.RoleService;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/**
 * Controller for all User Management including showing current user roles, editing and and deleting
 * users
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.USER_VIEW_NAME + "')")
public class UserMgmtController {
	private UserService userService;
	private RoleService roleService;

	public UserMgmtController(@Autowired UserService userService,
			@Autowired RoleService roleService) {
		this.userService = userService;
		this.roleService = roleService;
	}

	private static final List<Integer> VALID_USER_STATES = Arrays.asList(0, 1);

	private static final String USER_MGMT_REDIRECT = "redirect:/usermgmt";

	@GetMapping("/usermgmt")
	public WatchtowerModelAndView usermgmt() {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("admin/usermgmt");
		mv.addObject("users", userService.findAllUsers());
		mv.addScriptReference("/scripts/modal-delete-user.js");
		return mv;
	}

	@GetMapping("/usermgmt/edit/{id}")
	public WatchtowerModelAndView editUser(@PathVariable int id,
			RedirectAttributes redirectAttributes, Principal authenticatedUser) {
		WatchtowerModelAndView modelAndView = new WatchtowerModelAndView("admin/useredit");
		UserEntity user = userService.findById(id);

		if (user == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot find user.");
			modelAndView.setViewName(USER_MGMT_REDIRECT);
			return modelAndView;
		}

		modelAndView.addObject("user", user);
		modelAndView.addObject("roles", roleService.findAllRoles());

		return modelAndView;
	}

	@PostMapping("/usermgmt/edit")
	@PreAuthorize("hasAuthority('" + CorePrivilege.USER_MODIFY_NAME + "')")
	public String saveUser(@RequestParam long id, @RequestParam long role,
			@RequestParam int enabled, RedirectAttributes redirect, Principal authenticatedUser) {
		UserEntity user = userService.findById(id);
		RoleEntity roleEntity = roleService.findRoleById(role);
		String redirectTarget = USER_MGMT_REDIRECT;
		// Make sure user exists
		if (user == null) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot find user.");
		}
		// Make sure user is not trying to edit themselves
		else if (isCurrentUser(user, authenticatedUser)) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit own information.");
		}
		// Make sure enabled is a valid int
		else if (!VALID_USER_STATES.contains(enabled)) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Wrong value received for enabled.");
			redirectTarget = USER_MGMT_REDIRECT + "/edit/" + id;
		}
		// Make sure role exists
		else if (roleEntity == null && role != -1L) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown role selected.");
			redirectTarget = USER_MGMT_REDIRECT + "/edit/" + id;
		} else {
			// unset all roles
			if (role == -1) {
				user.setRoles(new HashSet<>());
			}
			// or add the correct one
			else {
				user.getRoles().add(roleEntity);
			}
			// Update enabled
			user.setEnabled(enabled);

			// Save user in database
			userService.updateUser(user);

			redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"User information for " + user.getUsername() + " saved successfully.");
		}
		return redirectTarget;
	}

	@PostMapping("/usermgmt/delete")
	@PreAuthorize("hasAuthority('" + CorePrivilege.USER_MODIFY_NAME + "')")
	public String deleteUser(@RequestParam int id, RedirectAttributes redirectAttributes,
			Principal authenticatedUser) {
		UserEntity user = userService.findById(id);

		if (user == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot delete user.");
			return USER_MGMT_REDIRECT;
		}

		if (isCurrentUser(user, authenticatedUser)) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot delete own account.");
			return USER_MGMT_REDIRECT;
		}

		user.getRoles().clear();
		userService.updateUser(user);
		userService.deleteUser(user);

		redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
				"User " + user.getUsername() + " deleted successfully");
		return USER_MGMT_REDIRECT;
	}

	/**
	 * Helper to determine if the given user is the same as the current authenticated user.
	 *
	 * @param user to compare with authenticated user
	 * @return true if the two users are equal, false otherwise
	 */
	private boolean isCurrentUser(UserEntity user, Principal authenticatedUser) {
		return user.getUsername().equals(authenticatedUser.getName());
	}
}
