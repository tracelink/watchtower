package com.tracelink.appsec.watchtower.core.scan.code.upload;

/**
 * Helper class to hold important information about an incoming Upload Scan Request
 *
 * @author csmith
 *
 */
public class UploadScan {

	private String name;

	private String ruleSet;

	private String storageKey;

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

	public String getStorageKey() {
		return storageKey;
	}

	public void setStorageKey(String storageKey) {
		this.storageKey = storageKey;
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
