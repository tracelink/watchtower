package com.tracelink.appsec.watchtower.core.rest.scan;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;

/**
 * An abstract class to represent a scan request submitted to Watchtower. Keeps track of the time
 * the scan was submitted.
 *
 * @author mcool
 */
public abstract class AbstractScan {

	private final long submitTime;
	private final String apiLabel;

	public AbstractScan(String apiLabel) {
		this.submitTime = System.currentTimeMillis();
		this.apiLabel = apiLabel;
	}

	public long getSubmitTime() {
		return submitTime;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	/**
	 * Given a String value of an HTTP Request Body, populate the data of this Scan request
	 * 
	 * @param requestBody the string value of the incoming HTTP Request
	 * @throws ApiIntegrationException if any value in the request is incorrect, or if the request
	 *                                 does not contain enough information to begin this scan
	 */
	public abstract void populateFromRequest(String requestBody) throws ApiIntegrationException;

	public abstract String getScanName();
}
