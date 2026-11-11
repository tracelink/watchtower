package com.tracelink.appsec.watchtower.core.scan.apiintegration;

/**
 * Thrown to indicate an issue has happened related to an {@linkplain ApiIntegrationEntity}
 *
 * @author csmith
 */
public class ApiIntegrationException extends Exception {

	private static final long serialVersionUID = -8693435059535652779L;

	public ApiIntegrationException(String message) {
		super(message);
	}
}
