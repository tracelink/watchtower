package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.ServletWebRequest;

class SafeErrorAttributesTest {
	@Test
	void replacesInternalMessagesAndAddsTheRequestId() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("jakarta.servlet.error.status_code", 500);
		request.setAttribute("jakarta.servlet.error.message", "database password leaked");
		request.setAttribute(RequestCorrelationFilter.REQUEST_ID_ATTRIBUTE, "request-123");

		Map<String, Object> attributes = new SafeErrorAttributes().getErrorAttributes(
				new ServletWebRequest(request), ErrorAttributeOptions.defaults());

		assertEquals("request-123", attributes.get("requestId"));
		assertEquals("The server could not complete this request.", attributes.get("safeMessage"));
		assertFalse(attributes.containsValue("database password leaked"));
		assertFalse(attributes.containsKey("trace"));
		assertFalse(attributes.containsKey("exception"));
	}
}
