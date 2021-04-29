package com.tracelink.appsec.watchtower.core.exception;

/**
 * An Exception used when a scan has been failed during the setup phase. Can be throw by anything
 * inside the scanner logic to denote that the scan can't/shouldn't proceed
 *
 * @author csmith
 */
public class ScanRejectedException extends Exception {

	private static final long serialVersionUID = 1536984801353368827L;

	public ScanRejectedException(String string) {
		super(string);
	}

	public ScanRejectedException(String string, Exception e) {
		super(string, e);
	}

}
