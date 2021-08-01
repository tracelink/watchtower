package com.tracelink.appsec.watchtower.core.exception.rule;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

/**
 * Exception thrown when a {@link RuleEntity} cannot be found in the database with a matching ID or
 * name.
 *
 * @author mcool
 */
public class RuleNotFoundException extends Exception {
	private static final long serialVersionUID = -1589050523546622928L;

	public RuleNotFoundException(String message) {
		super(message);
	}

	public RuleNotFoundException(String message, Throwable e) {
		super(message, e);
	}
}
