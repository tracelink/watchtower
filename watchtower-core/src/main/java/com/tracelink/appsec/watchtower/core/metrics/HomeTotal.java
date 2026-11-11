package com.tracelink.appsec.watchtower.core.metrics;

/**
 * One row of Home's "Total scans" table. Every scan type offers the same three actions; image scans
 * have no manual start ({@code newScanUrl} is null) because they begin when an image is pushed.
 */
public record HomeTotal(String type, String icon, long scans, long findings, String dashboardUrl,
		String resultsUrl, String newScanUrl) {

	public boolean isAutomatic() {
		return newScanUrl == null;
	}
}
