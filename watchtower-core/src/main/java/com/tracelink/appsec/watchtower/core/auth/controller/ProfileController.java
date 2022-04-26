package com.tracelink.appsec.watchtower.core.auth.controller;

import com.tracelink.appsec.watchtower.core.auth.model.ApiKeyEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.ApiUserService;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import java.security.KeyException;
import java.security.Principal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Controller for the profile editor. Allows changing passwords and managing API Keys
 *
 * @author csmith
 */
@Controller
@PreAuthorize("isAuthenticated()")
public class ProfileController {

	private UserService userService;

	private ApiUserService apiUserService;

	public ProfileController(@Autowired UserService userService,
			@Autowired ApiUserService apiUserService) {
		this.userService = userService;
		this.apiUserService = apiUserService;
	}

	@GetMapping("/profile")
	public WatchtowerModelAndView profile(Principal authenticatedUser) {
		UserEntity user = userService.findByUsername(authenticatedUser.getName());
		WatchtowerModelAndView modelAndView = new WatchtowerModelAndView("profile");

		modelAndView.addObject("user_name", user.getUsername());
		modelAndView.addObject("user_role", user.getRolesString());
		modelAndView.addObject("join_date", user.getCreated());
		modelAndView.addObject("local_user", user.getSsoId() == null);
		modelAndView.addObject("apiKeys", user.getApiKeys());
		modelAndView.addScriptReference("/scripts/profile.js");
		return modelAndView;
	}

	@PostMapping("/profile/changePassword")
	public String changePassword(RedirectAttributes redirectAttributes,
			@RequestParam String currentPassword,
			@RequestParam String newPassword, @RequestParam String confirmPassword,
			Principal authenticatedUser) {
		if (!newPassword.equals(confirmPassword)) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Your provided passwords don't match");
			return "redirect:/profile";
		}

		try {
			userService.changePassword(authenticatedUser.getName(), currentPassword, newPassword);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Your password has been updated successfully.");
		} catch (AuthenticationException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}

		return "redirect:/profile";
	}

	@PostMapping("/profile/apikey/create")
	public String createApiKey(@RequestParam String apiKeyLabel,
			RedirectAttributes redirectAttributes,
			Principal authenticatedUser) {
		UserEntity user = userService.findByUsername(authenticatedUser.getName());
		ApiKeyEntity apiKeyEntity = apiUserService.createUserApiKey(apiKeyLabel, user);
		redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
				"Created Key ID: " + apiKeyEntity.getApiKeyId() + " and Secret: "
						+ apiKeyEntity.getFirstTimeSecret());
		return "redirect:/profile";
	}

	@PostMapping("/profile/apikey/delete")
	public String deleteApiKey(@RequestParam String apiKeyId, RedirectAttributes redirectAttributes,
			Principal authenticatedUser) {
		UserEntity user = userService.findByUsername(authenticatedUser.getName());
		try {
			apiUserService.deleteUserApiKey(apiKeyId, user);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully deleted key " + apiKeyId);
		} catch (KeyException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/profile";
	}
}
