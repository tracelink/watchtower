package com.tracelink.appsec.watchtower.core.scan.image;

public abstract class AbstractImageScanReport {

	public abstract String getViolationMessages();

	public abstract boolean hasViolations();
}
