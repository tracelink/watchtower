package com.tracelink.appsec.watchtower.core.scan.image.result;

/**
 * DAO for Violations in a report found in an Image Scan
 * 
 * @author csmith
 *
 */
public class ImageScanResultViolation {
	private String violationName;
	private String severity;
	// The numeric RulePriority behind `severity` (1 High .. 6 Informational). The name alone is
	// enough to print, but not to colour the severity pill or to sort the column by priority
	// rather than alphabetically - PR and upload violations already carry both.
	private int severityValue;
	private String score;
	private String packageName;
	private String vector;
	private String description;
	private String uri;

	public String getViolationName() {
		return violationName;
	}

	public void setViolationName(String violationName) {
		this.violationName = violationName;
	}

	public String getSeverity() {
		return severity;
	}

	public void setSeverity(String severity) {
		this.severity = severity;
	}

	public int getSeverityValue() {
		return severityValue;
	}

	public void setSeverityValue(int severityValue) {
		this.severityValue = severityValue;
	}

	public String getScore() {
		return score;
	}

	public void setScore(String score) {
		this.score = score;
	}

	public String getPackageName() {
		return packageName;
	}

	public void setPackageName(String packageName) {
		this.packageName = packageName;
	}

	public String getVector() {
		return vector;
	}

	public void setVector(String vector) {
		this.vector = vector;
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
