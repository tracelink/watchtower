package com.tracelink.appsec.watchtower.core.scan.image.result;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.presentation.StatusPresentationModel;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;

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
	private ScanExecutionSummary executionSummary =
			new ScanExecutionSummary(null, Collections.emptyList());

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
		return com.tracelink.appsec.watchtower.core.ui.ServerTime.toEpochMillis(submitDate);
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

	@JsonIgnore
	public StatusPresentationModel getStatusPresentation() {
		return StatusPresentationModel.from(ScanStatus.toStatus(status));
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
		return com.tracelink.appsec.watchtower.core.ui.ServerTime.toEpochMillis(endDate);
	}

	public void setEndDate(LocalDateTime endDate) {
		this.endDate = endDate;
	}

	/** Submitted to finished, in the same format as every other scan list. */
	@JsonIgnore
	public String getDurationText() {
		return getEndDateMillis() > 0
				? com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem.formatDuration(
						getSubmitDateMillis(), getEndDateMillis())
				: "Not finished";
	}

	public List<ImageScanResultViolation> getViolations() {
		return violations;
	}

	public void setViolations(List<ImageScanResultViolation> violations) {
		this.violations = violations;
	}

	public ScanExecutionSummary getExecutionSummary() { return executionSummary; }

	/** The report's scanner tiles, the same as the other reports' Scanners row. */
	@JsonIgnore
	public com.tracelink.appsec.watchtower.core.scan.presentation.ScannerBadge.Summary getScannerTiles() {
		return com.tracelink.appsec.watchtower.core.scan.presentation.ScannerBadge.from(executionSummary.scanners(), null);
	}

	public void setExecutionSummary(ScanExecutionSummary value) {
		this.executionSummary = value == null
				? new ScanExecutionSummary(null, Collections.emptyList()) : value;
	}

}
