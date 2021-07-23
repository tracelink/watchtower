package com.tracelink.appsec.watchtower.core.module;

/**
 * Exception thrown when an illegal action is attempted for a {@link AbstractModule}, such as when a
 * name collision occurs.
 *
 * @author mcool
 */
public class ModuleException extends Exception {
	private static final long serialVersionUID = 1951873662798150240L;

	public ModuleException(String message) {
		super(message);
	}

	public ModuleException(String message, Throwable e) {
		super(message, e);
	}
}
