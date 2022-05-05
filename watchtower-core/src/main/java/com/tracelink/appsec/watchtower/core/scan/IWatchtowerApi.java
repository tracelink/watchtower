package com.tracelink.appsec.watchtower.core.scan;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Interface for common API integration functions to test connections to remote services and rgister
 * or unregister Watchtower scan webhooks.
 *
 * @author mcool
 */
public interface IWatchtowerApi {

	/**
	 * Test that this entity is configured correctly to connect to its remote service
	 *
	 * @throws ApiIntegrationException if the entity cannot connect to the remote service or does
	 *                                 not have the correct access
	 */
	void testClientConnection() throws ApiIntegrationException;

	/**
	 * Registers a Watchtower scan webhook for the remote service. May create credentials for the
	 * remote service to authenticate to Watchtower.
	 *
	 * @param passwordEncoder password encoder to hash any credentials
	 */
	void register(PasswordEncoder passwordEncoder);

	/**
	 * Unregisters the Watchtower scan webhook for the remote service.
	 */
	void unregister();
}
