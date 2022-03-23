package com.tracelink.appsec.watchtower.core.scan.api;

public interface IWatchtowerApi {
	/**
	 * Test that this entity is configured correctly to connect to its remote
	 * 
	 * @throws ApiIntegrationException if the entity cannot connect to the remote service or does
	 *                                 not have the correct access
	 */
	void testClientConnection() throws ApiIntegrationException;
}
