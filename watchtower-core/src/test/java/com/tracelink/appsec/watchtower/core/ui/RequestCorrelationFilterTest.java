package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class RequestCorrelationFilterTest {
	@Test
	void createsCorrelationIdAndReturnsItAsAResponseHeader() throws Exception {
		RequestCorrelationFilter filter = new RequestCorrelationFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, new MockFilterChain());

		Object requestId = request.getAttribute(RequestCorrelationFilter.REQUEST_ID_ATTRIBUTE);
		assertNotNull(requestId);
		assertEquals(requestId, response.getHeader(RequestCorrelationFilter.REQUEST_ID_HEADER));
	}

	@Test
	void acceptsAWellFormedIncomingCorrelationId() throws Exception {
		RequestCorrelationFilter filter = new RequestCorrelationFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(RequestCorrelationFilter.REQUEST_ID_HEADER, "client-request-123");
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, new MockFilterChain());

		assertEquals("client-request-123",
				request.getAttribute(RequestCorrelationFilter.REQUEST_ID_ATTRIBUTE));
	}
}
