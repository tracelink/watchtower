package com.tracelink.appsec.watchtower.core.module;

/**
 * Exception thrown when a corresponding {@link AbstractModule} cannot be found
 * for a given name.
 *
 * @author mcool
 */
public class ModuleNotFoundException extends Exception {
	private static final long serialVersionUID = 6228618614794353318L;

	public ModuleNotFoundException(String message) {
		super(message);
	}
}
