package com.tracelink.appsec.watchtower.core.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class PublicEndpointRateLimitFilterTest {

	@Test
	void rejectsRequestsOverThePerClientLimit() throws Exception {
		PublicEndpointRateLimitFilter filter = new PublicEndpointRateLimitFilter(2, 60);
		MockHttpServletRequest request = request("/login", "192.0.2.1");

		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		MockHttpServletResponse rejected = new MockHttpServletResponse();
		filter.doFilter(request, rejected, new MockFilterChain());

		assertEquals(429, rejected.getStatus());
		assertEquals("60", rejected.getHeader("Retry-After"));
	}

	@Test
	void clientsHaveIndependentBudgets() throws Exception {
		PublicEndpointRateLimitFilter filter = new PublicEndpointRateLimitFilter(1, 60);
		filter.doFilter(request("/register", "192.0.2.1"), new MockHttpServletResponse(),
				new MockFilterChain());
		MockHttpServletResponse otherClient = new MockHttpServletResponse();

		filter.doFilter(request("/register", "192.0.2.2"), otherClient, new MockFilterChain());

		assertEquals(200, otherClient.getStatus());
	}

	@Test
	void ignoresAuthenticatedApplicationPaths() throws Exception {
		PublicEndpointRateLimitFilter filter = new PublicEndpointRateLimitFilter(1, 60);
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request("/dashboard", "192.0.2.1"), response, new MockFilterChain());

		assertEquals(200, response.getStatus());
	}

	/**
	 * Bitbucket sends a pullrequest:comment_created delivery for every PR comment in the
	 * workspace. Those must never use up the budget that real scan deliveries need.
	 */
	@Test
	void commentDeliveriesNeverUseTheScanBudget() throws Exception {
		PublicEndpointRateLimitFilter filter = new PublicEndpointRateLimitFilter(1, 2, 60);
		for (int i = 0; i < 5; i++) {
			filter.doFilter(comment(), new MockHttpServletResponse(), new MockFilterChain());
		}
		MockHttpServletResponse scan = new MockHttpServletResponse();

		filter.doFilter(event("pullrequest:updated"), scan, new MockFilterChain());

		assertEquals(200, scan.getStatus());
	}

	@Test
	void commentDeliveriesHaveTheirOwnLimit() throws Exception {
		PublicEndpointRateLimitFilter filter = new PublicEndpointRateLimitFilter(1, 2, 60);
		filter.doFilter(comment(), new MockHttpServletResponse(), new MockFilterChain());
		filter.doFilter(comment(), new MockHttpServletResponse(), new MockFilterChain());
		MockHttpServletResponse rejected = new MockHttpServletResponse();

		filter.doFilter(comment(), rejected, new MockFilterChain());

		assertEquals(429, rejected.getStatus());
	}

	@Test
	void eachIntegrationHasItsOwnCommentBudget() throws Exception {
		// Bitbucket delivers every workspace from the same few addresses: one busy workspace's
		// comments must not use up another's.
		PublicEndpointRateLimitFilter filter = new PublicEndpointRateLimitFilter(1, 1, 60);
		filter.doFilter(comment(), new MockHttpServletResponse(), new MockFilterChain());
		MockHttpServletRequest other = request("/rest/scan/other-workspace", "192.0.2.1");
		other.addHeader("X-Event-Key", "pullrequest:comment_created");
		MockHttpServletResponse otherResponse = new MockHttpServletResponse();

		filter.doFilter(other, otherResponse, new MockFilterChain());

		assertEquals(200, otherResponse.getStatus());
	}

	@Test
	void scanDeliveriesKeepTheirLimit() throws Exception {
		PublicEndpointRateLimitFilter filter = new PublicEndpointRateLimitFilter(1, 100, 60);
		filter.doFilter(event("pullrequest:created"), new MockHttpServletResponse(),
				new MockFilterChain());
		MockHttpServletResponse rejected = new MockHttpServletResponse();

		filter.doFilter(event("pullrequest:updated"), rejected, new MockFilterChain());

		assertEquals(429, rejected.getStatus());
	}

	private MockHttpServletRequest comment() {
		return event("pullrequest:comment_created");
	}

	private MockHttpServletRequest event(String eventKey) {
		MockHttpServletRequest request = request("/rest/scan/bitbucket", "192.0.2.1");
		request.addHeader("X-Event-Key", eventKey);
		return request;
	}

	private MockHttpServletRequest request(String path, String address) {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
		request.setRemoteAddr(address);
		return request;
	}
}
