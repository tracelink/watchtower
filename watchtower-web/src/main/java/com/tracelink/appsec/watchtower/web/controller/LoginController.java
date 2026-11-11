package com.tracelink.appsec.watchtower.web.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import com.tracelink.appsec.watchtower.core.handler.WatchtowerAuthFailureHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

/**
 * Controller for the login page. Only serves the custom login page.
 *
 * @author csmith
 */
@Controller
public class LoginController {

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final boolean allowRegistration;

	public LoginController(
			@Autowired(required = false) ClientRegistrationRepository clientRegistrationRepository,
			@Value(value = "${watchtower.allowRegistration:true}") boolean allowRegistration) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.allowRegistration = allowRegistration;
	}

	@GetMapping("/login")
	public ModelAndView login(HttpServletRequest request) {
		ModelAndView mav = new ModelAndView();
		mav.setViewName(clientRegistrationRepository == null
				|| clientRegistrationRepository.findByRegistrationId("oidc") == null ? "login"
						: "login-sso");
		mav.addObject("allowRegistration", allowRegistration);
		mav.addObject("hasLoginError", request.getParameter("error") != null);
		HttpSession session = request.getSession(false);
		if (session != null) {
			Object username = session.getAttribute(WatchtowerAuthFailureHandler.LAST_LOGIN_USERNAME);
			if (username instanceof String) {
				mav.addObject("loginUsername", username);
				session.removeAttribute(WatchtowerAuthFailureHandler.LAST_LOGIN_USERNAME);
			}
		}
		return mav;
	}

}
