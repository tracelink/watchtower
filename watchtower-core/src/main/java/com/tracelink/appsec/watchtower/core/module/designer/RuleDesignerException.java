package com.tracelink.appsec.watchtower.core.module.designer;

/**
 * Thrown if there is a problem during Rule Design or Rule Querying
 * 
 * @author csmith
 *
 */
public class RuleDesignerException extends Exception {

	private static final long serialVersionUID = 2484992976515134998L;

	public RuleDesignerException(String message) {
		super(message);
	}
}
