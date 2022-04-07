package com.tracelink.appsec.watchtower.core.scan.image;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class ImageSecurityFinding {

	private RulePriority severity;

	private String packageName;

	private String packageVersion;

	private String score;

	private String vector;

	private String findingName;

	private String description;

	private String uri;

	public RulePriority getSeverity() {
		return severity;
	}

	public void setSeverity(RulePriority severity) {
		this.severity = severity;
	}

	public String getPackageName() {
		return packageName;
	}

	public void setPackageName(String packageName) {
		this.packageName = packageName;
	}

	public String getPackageVersion() {
		return packageVersion;
	}

	public void setPackageVersion(String packageVersion) {
		this.packageVersion = packageVersion;
	}

	public String getScore() {
		return score;
	}

	public void setScore(String score) {
		this.score = score;
	}

	public String getVector() {
		return vector;
	}

	public void setVector(String vector) {
		this.vector = vector;
	}

	public String getFindingName() {
		return findingName;
	}

	public void setFindingName(String findingName) {
		this.findingName = findingName;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getUri() {
		return uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}


}
