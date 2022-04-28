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

	public abstract void populateFromRequest(String requestBody) throws ApiIntegrationException;

	public abstract String getScanName();
}
