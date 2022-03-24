package com.tracelink.appsec.watchtower.core.scan.code.pr.result;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;

/**
 * Helper class to hold important information about the results of a PR scan
 * 
 * @author csmith
 *
 */
public class PRScanResult {
	private long id;

	private String prId;

	private String displayName;

	private String author;

	private LocalDateTime date;

	private String prLink;

	private String apiLabel;

	private String repoName;

	private List<PRScanResultViolation> violations;

	public void setId(long id) {
		this.id = id;
	}

	public long getId() {
		return this.id;
	}

	public String getPrId() {
		return prId;
	}

	public void setPrId(String id) {
		this.prId = id;
	}

	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}

	public LocalDateTime getDate() {
		return date;
	}

	public void setDate(LocalDateTime date) {
		this.date = date;
	}

	public long getDateMillis() {
		return date.toInstant(ZoneOffset.UTC).toEpochMilli();
	}

	public String getPrLink() {
		return prLink;
	}

	public void setPrLink(String prLink) {
		this.prLink = prLink;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getRepoName() {
		return repoName;
	}

	public void setRepoName(String repoName) {
		this.repoName = repoName;
	}

	public List<PRScanResultViolation> getViolations() {
		return violations;
	}

	public void setViolations(List<PRScanResultViolation> violations) {
		this.violations = violations;
	}

}
