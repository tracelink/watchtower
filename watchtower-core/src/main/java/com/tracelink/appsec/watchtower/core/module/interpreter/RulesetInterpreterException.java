package com.tracelink.appsec.watchtower.core.module.interpreter;

/**
 * Exception that is thrown if there is a problem during ruleset import or export.
 *
 * @author mcool
 */
public class RulesetInterpreterException extends Exception {

	private static final long serialVersionUID = 1584470181139165371L;

	public RulesetInterpreterException(String message) {
		super(message);
	}
}
