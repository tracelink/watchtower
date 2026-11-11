package com.tracelink.appsec.watchtower.core.ui;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Assigns a safe correlation ID to each HTTP request and response. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestCorrelationFilter extends OncePerRequestFilter {
	public static final String REQUEST_ID_HEADER = "X-Request-ID";
	public static final String REQUEST_ID_ATTRIBUTE = "watchtowerRequestId";
	private static final Pattern SAFE_REQUEST_ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {
		String incoming = request.getHeader(REQUEST_ID_HEADER);
		String requestId = incoming != null && SAFE_REQUEST_ID.matcher(incoming).matches()
				? incoming : UUID.randomUUID().toString();
		request.setAttribute(REQUEST_ID_ATTRIBUTE, requestId);
		response.setHeader(REQUEST_ID_HEADER, requestId);
		filterChain.doFilter(request, response);
	}
}
