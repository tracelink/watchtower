package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

/**
 * A bypass or revoke that was refused. The message is safe to show the user.
 *
 * @author Watchtower
 */
public class PRScanBypassException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public PRScanBypassException(String message) {
		super(message);
	}
}
