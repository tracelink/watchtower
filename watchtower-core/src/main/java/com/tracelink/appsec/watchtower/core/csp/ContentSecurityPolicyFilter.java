package com.tracelink.appsec.watchtower.core.csp;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.GenericFilterBean;

/**
 * A Filter to handle creating a CSP for all pages.
 * 
 * @author mcool
 *
 */
public class ContentSecurityPolicyFilter extends GenericFilterBean {
	private static final String CSP_DEFAULT =
			"object-src 'none'; script-src 'nonce-%s' 'unsafe-inline' 'strict-dynamic' https: http:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; report-uri /rest/csp/report";
	private static final String CSP_CONSOLE =
			"object-src 'none'; script-src 'unsafe-inline' http: https:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; report-uri /rest/csp/report";
	private final SecureRandom secureRandom = new SecureRandom();

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		byte[] nonceBytes = new byte[32];
		secureRandom.nextBytes(nonceBytes);
		String nonce = Base64.getEncoder().encodeToString(nonceBytes);
		request.setAttribute("nonce", nonce);
		String path = ((HttpServletRequest) request).getRequestURI()
				.substring(((HttpServletRequest) request).getContextPath().length());
		// If we are trying to access H2 console, modify CSP to allow JS to function
		String policy = "/console".equals(path) || path.startsWith("/console/") ? CSP_CONSOLE
				: String.format(CSP_DEFAULT, nonce);
		// Set CSP header on response
		((HttpServletResponse) response).setHeader("Content-Security-Policy-Report-Only", policy);
		if (chain != null) {
			chain.doFilter(request, response);
		}
	}
}
