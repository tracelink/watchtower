package com.tracelink.appsec.watchtower.core.scan.code.upload;

import java.nio.file.Path;

/**
 * Helper class to hold important information about an incoming Upload Scan Request
 * 
 * @author csmith
 *
 */
public class UploadScan {

	private String name;

	private String ruleSet;

	private Path filePath;

	private String user;

	private long submitted;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getRuleSetName() {
		return ruleSet;
	}

	public void setRuleSetName(String ruleSet) {
		this.ruleSet = ruleSet;
	}

	public Path getFilePath() {
		return filePath;
	}

	public void setFilePath(Path filePath) {
		this.filePath = filePath;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public void setSubmitDate(long submitted) {
		this.submitted = submitted;
	}

	public long getSubmitDate() {
		return submitted;
	}

}
