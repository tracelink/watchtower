package com.tracelink.appsec.watchtower.core.scan;

import com.tracelink.appsec.watchtower.core.auth.model.ApiKeyEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import java.util.function.Consumer;
import java.util.function.Function;

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
	 * Registers a Watchtower scan webhook for the remote service, and updates the status of the API
	 * integration entity associated with this API. May create a programmatic API key for the remote
	 * service to authenticate to Watchtower.
	 *
	 * @param apiKeyFunction        function to create a new programmatic API key from an apiLabel
	 * @param registerStateConsumer consumer to save register state on the API integration entity
	 */
	void register(Function<String, ApiKeyEntity> apiKeyFunction,
			Consumer<ApiIntegrationEntity> registerStateConsumer);

	/**
	 * Unregisters the Watchtower scan webhook for the remote service, and updates the status of
	 * the API integration entity associated with this API. Responsible for deleting the
	 * programmatic API key that the remote service used to authenticate to Watchtower.
	 *
	 * @param apiKeyConsumer        consumer to delete a programmatic API key from an apiLabel
	 * @param registerStateConsumer consumer to save register state on the API integration entity
	 */
	void unregister(Consumer<String> apiKeyConsumer,
			Consumer<ApiIntegrationEntity> registerStateConsumer);
}
