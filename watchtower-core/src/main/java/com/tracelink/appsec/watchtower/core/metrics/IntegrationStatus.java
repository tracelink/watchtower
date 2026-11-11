package com.tracelink.appsec.watchtower.core.metrics;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.RegisterState;

/**
 * One configured integration on Home's status panel: its last recorded connection test and webhook
 * registration as chips. A failed test is summarized; the error itself stays on the Integrations
 * page, which only integration administrators can open.
 */
public record IntegrationStatus(String label, String provider, String icon, String connection,
		String connectionText, String connectionTip, String webhook, String webhookText,
		String webhookTip) {
	public static final String OK = "ok";
	public static final String WARN = "warn";
	public static final String BAD = "bad";

	public static IntegrationStatus from(ApiIntegrationEntity integration) {
		ApiType type = integration.getApiType();
		String provider = (type == null ? "Integration" : type.getTypeName())
				+ (type == ApiType.ECR ? " · images" : " · pull requests");
		String icon = type == ApiType.ECR ? "inventory_2" : "call_merge";
		Boolean healthy = integration.getHealthOk();
		String connection = healthy == null ? WARN : healthy ? OK : BAD;
		String connectionText = healthy == null ? "Not tested" : healthy ? "Connected" : "Failing";
		String connectionTip = healthy == null ? "No connection test has been recorded yet."
				: healthy ? "The last connection test passed."
						: "The last connection test failed. Open Integrations for the error.";
		RegisterState state = integration.getRegisterState();
		String webhook = state == null || state == RegisterState.NOT_SUPPORTED ? null
				: state == RegisterState.REGISTERED ? OK : WARN;
		String webhookText = state == null ? null : switch (state) {
			case REGISTERED -> "Webhook on";
			case IN_PROGRESS -> "Webhook pending";
			case FAILED -> "Webhook failed";
			case NOT_REGISTERED -> "Webhook off";
			case NOT_SUPPORTED -> null;
		};
		String webhookTip = state == RegisterState.REGISTERED
				? "Scans start automatically from provider events."
				: "Webhook not registered: scans are not triggered automatically.";
		return new IntegrationStatus(integration.getApiLabel(), provider, icon, connection,
				connectionText, connectionTip, webhook, webhookText, webhookTip);
	}
}
