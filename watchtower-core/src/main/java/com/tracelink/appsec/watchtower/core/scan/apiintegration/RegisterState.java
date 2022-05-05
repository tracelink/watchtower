package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.util.Arrays;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;

/**
 * Represents the state of a Watchtower scan webhook for a remote service. Each API integration
 * entity keeps track of the webhooks registered state.
 *
 * @author mcool
 */
public enum RegisterState {
	NOT_SUPPORTED, // If the remote service does not support automatic registration
	NOT_REGISTERED, // If the webhook has not been registered yet
	IN_PROGRESS, // If the webhook registration is in progress asynchronously
	REGISTERED, // If the webhook is successfully registered
	FAILED; // If the webhook registration has failed

	/**
	 * Gets a display name in title case for this register state, replacing underscores with spaces
	 *
	 * @return display name for this register state
	 */
	public String getDisplayName() {
		return Arrays.stream(name().split("_"))
				.map(String::toLowerCase)
				.map(StringUtils::capitalize)
				.collect(Collectors.joining(" "));
	}
}
