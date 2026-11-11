package com.tracelink.appsec.watchtower.core.handler;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

/**
 * Handler to distinguish between different authentication failure events and respond to the user
 * with an appropriate message.
 *
 * @author csmith, mcool
 */
public class WatchtowerAuthFailureHandler extends SimpleUrlAuthenticationFailureHandler {
	public static final String LAST_LOGIN_USERNAME =
			WatchtowerAuthFailureHandler.class.getName() + ".LAST_LOGIN_USERNAME";

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		String error = "Invalid Login";
		String username = request.getParameter("username");
		if (username != null && !username.isBlank()) {
			request.getSession().setAttribute(LAST_LOGIN_USERNAME,
					username.length() > 255 ? username.substring(0, 255) : username);
		}
		if (exception instanceof DisabledException) {
			error = "Account Disabled";
		} else if (exception instanceof OAuth2AuthenticationException) {
			error = "SSO Login Failed";
		}
		getRedirectStrategy().sendRedirect(request, response,
				"/login?error=" + URLEncoder.encode(error, StandardCharsets.UTF_8));
	}

}
