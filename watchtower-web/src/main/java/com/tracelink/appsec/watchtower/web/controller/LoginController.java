package com.tracelink.appsec.watchtower.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Controller for the login page. Only serves the custom login page.
 *
 * @author csmith
 */
@Controller
public class LoginController {

	private final ClientRegistrationRepository clientRegistrationRepository;

	public LoginController(@Autowired(required = false) ClientRegistrationRepository clientRegistrationRepository) {
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@GetMapping("/login")
	public String login() {
		return clientRegistrationRepository == null
				|| clientRegistrationRepository.findByRegistrationId("oidc") == null ? "login"
				: "login-sso";
	}

}
