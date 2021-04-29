package com.tracelink.appsec.watchtower.core.scan.processor;

/**
 * Denotes when a processor could not complete its setup tasks (before a scan even starts)
 * 
 * @author csmith
 *
 */
public class ProcessorSetupException extends Exception {

	private static final long serialVersionUID = -2041891653794604579L;

	public ProcessorSetupException(Exception e) {
		super(e);
	}
}
