package com.tracelink.appsec.watchtower.core.auth.controller;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
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
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.RoleService;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;

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

	/** A last login older than this many days is shown in amber on the Users page. */
	static final int STALE_LOGIN_DAYS = 90;

	@GetMapping("/usermgmt")
	public WatchtowerModelAndView usermgmt(@RequestParam(defaultValue = "0") int page,
			Principal authenticatedUser) {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("admin/usermgmt");
		if (page < 0) {
			mv.setViewName(USER_MGMT_REDIRECT + "?page=0");
			return mv;
		}
		PageRequest pageable = PageRequest.of(page, 10, Sort.by("username"));
		Page<UserEntity> users = userService.findUsers(pageable);
		if (users == null) {
			List<UserEntity> allUsers = userService.findAllUsers();
			users = new PageImpl<>(allUsers, pageable, allUsers.size());
		}
		PagedResult<UserEntity> pagination = PagedResult.of(users, user -> user);
		if (pagination.totalPages() > 0 && page >= pagination.totalPages()) {
			mv.setViewName(USER_MGMT_REDIRECT + "?page=" + (pagination.totalPages() - 1));
			return mv;
		}
		mv.addObject("users", pagination.content());
		mv.addObject("hasUsers", !pagination.content().isEmpty());
		mv.addObject("pagination", pagination);
		// Your own row shows "You" instead of Delete (deleting yourself is refused anyway), and
		// logins older than STALE_LOGIN_DAYS are flagged so unused accounts stand out.
		mv.addObject("currentUsername", authenticatedUser == null ? null : authenticatedUser.getName());
		mv.addObject("staleLoginBefore", LocalDateTime.now().minusDays(STALE_LOGIN_DAYS));
		mv.addObject("staleLoginDays", STALE_LOGIN_DAYS);
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
		modelAndView.addObject("selectedRoleIds", user.getRoles().stream().map(RoleEntity::getId).collect(java.util.stream.Collectors.toSet()));

		return modelAndView;
	}

	@PostMapping("/usermgmt/edit")
	@PreAuthorize("hasAuthority('" + CorePrivilege.USER_MODIFY_NAME + "')")
	@org.springframework.transaction.annotation.Transactional
	public String saveUser(@RequestParam long id, @RequestParam boolean rolesSubmitted,
			@RequestParam(required = false) java.util.Set<Long> roleIds,
			@RequestParam(defaultValue = "0") int enabled, RedirectAttributes redirect,
			Principal authenticatedUser) {
		UserEntity user = userService.findById(id);
		java.util.Set<Long> submitted = roleIds == null ? java.util.Set.of() : roleIds;
		var selectedRoles = new HashSet<RoleEntity>();
		for (Long roleId : submitted) {
			RoleEntity role = roleId == null ? null : roleService.findRoleById(roleId);
			if (role != null) selectedRoles.add(role);
		}
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
		else if (!rolesSubmitted || selectedRoles.size() != submitted.size()) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown role selected.");
			redirectTarget = USER_MGMT_REDIRECT + "/edit/" + id;
		} else {
			user.setRoles(selectedRoles);
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
