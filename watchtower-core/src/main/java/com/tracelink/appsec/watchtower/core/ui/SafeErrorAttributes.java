package com.tracelink.appsec.watchtower.core.ui;

import java.util.Map;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.webmvc.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

/** Supplies error views with recovery-safe presentation data and no exception details. */
@Component
public class SafeErrorAttributes extends DefaultErrorAttributes {
	@Override
	public Map<String, Object> getErrorAttributes(WebRequest webRequest,
			ErrorAttributeOptions options) {
		Map<String, Object> attributes = super.getErrorAttributes(webRequest,
				ErrorAttributeOptions.defaults());
		attributes.remove("message");
		attributes.remove("trace");
		attributes.remove("exception");
		int status = attributes.get("status") instanceof Number number ? number.intValue() : 500;
		attributes.put("safeMessage", safeMessage(status));
		attributes.put("retryable", status == 408 || status == 429 || status >= 500);
		attributes.put("requestId",
				webRequest.getAttribute(RequestCorrelationFilter.REQUEST_ID_ATTRIBUTE,
						WebRequest.SCOPE_REQUEST));
		return attributes;
	}

	private String safeMessage(int status) {
		return switch (status) {
			case 400 -> "The request could not be understood. Check the submitted values and try again.";
			case 401 -> "Sign in to continue.";
			case 403 -> "You do not have permission to access this resource.";
			case 404 -> "The requested page could not be found.";
			default -> "The server could not complete this request.";
		};
	}
}
