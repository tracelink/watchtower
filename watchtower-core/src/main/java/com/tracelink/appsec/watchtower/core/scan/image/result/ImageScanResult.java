package com.tracelink.appsec.watchtower.core.scan.image.result;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/**
 * DAO containing information about the result of an Image Scan
 * 
 * @author csmith
 *
 */
public class ImageScanResult {
	private long id;
	private String apiLabel;
	private String repositoryName;
	private String tagName;
	private LocalDateTime submitDate;
	private String status;
	private String errorMessage;
	private LocalDateTime endDate;
	private List<ImageScanResultViolation> violations = new ArrayList<>();

	public void setId(long id) {
		this.id = id;
	}

	public long getId() {
		return id;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getRepositoryName() {
		return repositoryName;
	}

	public void setRepositoryName(String repositoryName) {
		this.repositoryName = repositoryName;
	}

	public String getTagName() {
		return tagName;
	}

	public void setTagName(String tagName) {
		this.tagName = tagName;
	}

	public LocalDateTime getSubmitDate() {
		return submitDate;
	}

	public long getSubmitDateMillis() {
		return submitDate.toInstant(ZoneOffset.UTC).toEpochMilli();
	}

	public void setSubmitDate(LocalDateTime submitDate) {
		this.submitDate = submitDate;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	public LocalDateTime getEndDate() {
		return endDate;
	}

	public long getEndDateMillis() {
		return endDate.toInstant(ZoneOffset.UTC).toEpochMilli();
	}

	public void setEndDate(LocalDateTime endDate) {
		this.endDate = endDate;
	}

	public List<ImageScanResultViolation> getViolations() {
		return violations;
	}

	public void setViolations(List<ImageScanResultViolation> violations) {
		this.violations = violations;
	}

}
