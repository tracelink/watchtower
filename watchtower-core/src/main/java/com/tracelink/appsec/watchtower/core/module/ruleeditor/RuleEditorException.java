package com.tracelink.appsec.watchtower.core.module.ruleeditor;

/**
 * Thrown if there is a problem during Rule Editing
 * 
 * @author csmith
 *
 */
public class RuleEditorException extends Exception {
	private static final long serialVersionUID = 951291521837313797L;

	public RuleEditorException(String message) {
		super(message);
	}
}
