package com.tracelink.appsec.watchtower.web.controller;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.mock.web.MockHttpServletRequest;
import com.tracelink.appsec.watchtower.core.handler.WatchtowerAuthFailureHandler;

public class LoginControllerTest {
	///////////////////
	// Get login
	///////////////////
	@Test
	public void testGetLogin() {
		ModelAndView mav = new LoginController(null, true)
				.login(new MockHttpServletRequest());
		Assertions.assertEquals("login", mav.getViewName());
		Assertions.assertEquals(true, mav.getModel().get("allowRegistration"));
		Assertions.assertEquals(false, mav.getModel().get("hasLoginError"));
	}

	@Test
	public void testGetLoginWithError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("error", "Invalid username or password.");

		ModelAndView mav = new LoginController(null, true).login(request);

		Assertions.assertEquals(true, mav.getModel().get("hasLoginError"));
	}

	@Test
	public void testGetLoginSso() {
		ClientRegistration clientRegistration =
				ClientRegistration.withRegistrationId("oidc").authorizationGrantType(
						AuthorizationGrantType.AUTHORIZATION_CODE).clientId("foo")
						.tokenUri("/bar").authorizationUri("/auth").redirectUri("/redirect")
						.build();
		ClientRegistrationRepository clientRegistrationRepository =
				registrationId -> "oidc".equals(registrationId) ? clientRegistration : null;
		LoginController loginController = new LoginController(clientRegistrationRepository, true);
		ModelAndView mav = loginController.login(new MockHttpServletRequest());
		Assertions.assertEquals("login-sso", mav.getViewName());
	}

	@Test
	public void testGetLoginNoRegister() {
		LoginController loginController = new LoginController(null, false);
		ModelAndView mav = loginController.login(new MockHttpServletRequest());
		Assertions.assertEquals("login", mav.getViewName());
		Assertions.assertEquals(false, mav.getModel().get("allowRegistration"));
	}

	@Test
	public void testFailedUsernameIsConsumedOnce() {
		LoginController loginController = new LoginController(null, false);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.getSession().setAttribute(WatchtowerAuthFailureHandler.LAST_LOGIN_USERNAME,
				"developer@example.test");

		ModelAndView first = loginController.login(request);
		ModelAndView second = loginController.login(request);

		Assertions.assertEquals("developer@example.test", first.getModel().get("loginUsername"));
		Assertions.assertFalse(second.getModel().containsKey("loginUsername"));
	}

}
