package com.tracelink.appsec.watchtower.core.rule;

/**
 * Exception class denoting that a rule issue has been encountered
 * 
 * @author csmith
 *
 */
public class RuleException extends Exception {

	private static final long serialVersionUID = 5252236645013894701L;

	public RuleException(String msg) {
		super(msg);
	}

	public RuleException(String msg, Exception e) {
		super(msg, e);
	}
}
