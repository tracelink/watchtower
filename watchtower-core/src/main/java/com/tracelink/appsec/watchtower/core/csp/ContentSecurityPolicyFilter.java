package com.tracelink.appsec.watchtower.core.csp;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.filter.GenericFilterBean;

/**
 * A Filter to handle creating a CSP for all pages.
 * 
 * @author mcool
 *
 */
public class ContentSecurityPolicyFilter extends GenericFilterBean {
	private static final String CSP_DEFAULT =
			"default-src 'self'; object-src 'none'; script-src 'nonce-%s' 'strict-dynamic' https:; "
			+ "img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; "
			+ "base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "
			+ "report-uri /rest/csp/report";
	private final SecureRandom secureRandom = new SecureRandom();

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		byte[] nonceBytes = new byte[32];
		secureRandom.nextBytes(nonceBytes);
		String nonce = Base64.getEncoder().encodeToString(nonceBytes);
		request.setAttribute("nonce", nonce);
		String policy = String.format(CSP_DEFAULT, nonce);
		((HttpServletResponse) response).setHeader("Content-Security-Policy", policy);
		if (chain != null) {
			chain.doFilter(request, response);
		}
	}
}
