package com.tracelink.appsec.watchtower.core.handler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

class WatchtowerAuthFailureHandlerTest {

	private final WatchtowerAuthFailureHandler handler = new WatchtowerAuthFailureHandler();

	@Test
	void preservesUsernameAndUsesSafeLocalMessage() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("username", "developer@example.test");
		MockHttpServletResponse response = new MockHttpServletResponse();

		handler.onAuthenticationFailure(request, response,
				new BadCredentialsException("database details must stay private"));

		assertEquals("developer@example.test", request.getSession().getAttribute(
				WatchtowerAuthFailureHandler.LAST_LOGIN_USERNAME));
		assertEquals("/login?error=Invalid+Login", response.getRedirectedUrl());
		assertFalse(response.getRedirectedUrl().contains("database"));
	}

	@Test
	void oauthFailureDoesNotExposeProviderExceptionText() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		OAuth2AuthenticationException exception = new OAuth2AuthenticationException(
				new OAuth2Error("provider_error"), "internal provider response");

		handler.onAuthenticationFailure(request, response, exception);

		assertEquals("/login?error=SSO+Login+Failed", response.getRedirectedUrl());
		assertFalse(response.getRedirectedUrl().contains("provider"));
	}
}
