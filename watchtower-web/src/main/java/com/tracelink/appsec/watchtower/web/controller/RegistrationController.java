package com.tracelink.appsec.watchtower.web.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserRegistrationForm;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/**
 * Controller for the registration flow.
 *
 * @author csmith
 */
@Controller
public class RegistrationController {
	private UserService userService;

	public RegistrationController(@Autowired UserService userService) {
		this.userService = userService;
	}

	@GetMapping("/register")
	public String registerForm(UserRegistrationForm form) {
		return "register";
	}

	@PostMapping("/register")
	public ModelAndView registerUser(@Valid @ModelAttribute UserRegistrationForm form,
			BindingResult bindingResult, RedirectAttributes redirectAttributes) {
		ModelAndView modelAndView = new ModelAndView();

		UserEntity userExists = userService.findByUsername(form.getUsername());

		if (userExists != null) {
			bindingResult.rejectValue("username", "error.user",
					"User with that username already exists");
		}

		if (!form.getPassword().equals(form.getPasswordConfirmation())) {
			bindingResult.rejectValue("passwordConfirmation", "error.user",
					"Passwords don't match");
		}

		if (bindingResult.hasErrors()) {
			modelAndView.setViewName("register");
		} else {
			userService.registerNewUser(form.getUsername(), form.getPassword());

			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"User account created successfully. Please sign in.");

			modelAndView.setViewName("redirect:/login");
		}

		return modelAndView;
	}
}
