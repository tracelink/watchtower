package com.tracelink.appsec.watchtower.core.csp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class ContentSecurityPolicyFilterTest {

	@Test
	void sendsAnEnforcedNonceBasedPolicy() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
		MockHttpServletResponse response = new MockHttpServletResponse();

		new ContentSecurityPolicyFilter().doFilter(request, response, new MockFilterChain());

		String policy = response.getHeader("Content-Security-Policy");
		assertNotNull(policy);
		assertTrue(policy.contains("script-src 'nonce-"));
		assertTrue(policy.contains("frame-ancestors 'none'"));
		assertFalse(policy.contains(" http:"));
		assertNull(response.getHeader("Content-Security-Policy-Report-Only"));
		assertNotNull(request.getAttribute("nonce"));
	}
}
