package com.tracelink.appsec.module.regex.scanner;

import com.tracelink.appsec.watchtower.core.benchmark.TimerType;

/**
 * Additional benchmarking timers for Regex Scans
 *
 * @author csmith
 */
public enum RegexTimerType implements TimerType {
	RULES_GENERATE("Generate Rules");
	private final String extName;

	RegexTimerType(String externalName) {
		this.extName = externalName;
	}

	public String getExternalName() {
		return this.extName;
	}
}
