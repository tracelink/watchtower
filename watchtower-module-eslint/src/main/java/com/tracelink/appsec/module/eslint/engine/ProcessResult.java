package com.tracelink.appsec.module.eslint.engine;

import org.apache.commons.lang3.StringUtils;

/**
 * Holds the result of a {@link Process}, including the results of the command and any errors that
 * occurred.
 *
 * @author mcool
 */
public class ProcessResult {

	private final String results;

	private final String errors;

	public ProcessResult(String results, String errors) {
		this.results = results;
		this.errors = errors;
	}

	public String getResults() {
		return results;
	}

	public boolean hasResults() {
		return StringUtils.isNotBlank(results);
	}

	public String getErrors() {
		return errors;
	}

	public boolean hasErrors() {
		return StringUtils.isNotBlank(errors);
	}
}
