package com.tracelink.appsec.watchtower.core.scan.code.upload.result;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScanFailure;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScannerBadge;
import com.tracelink.appsec.watchtower.core.scan.presentation.StatusPresentationModel;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Collections;

/**
 * Helper class to hold important information about the results of an Upload scan
 * 
 * @author csmith
 *
 */
public class UploadScanResult {

	private String name;

	private String submittedBy;

	private String status;

	private String error;

	private String ticket;

	private String ruleset;

	private LocalDateTime submitDate;

	private LocalDateTime endDate;

	private List<UploadScanResultViolation> violations;
	private ScanExecutionSummary executionSummary =
			new ScanExecutionSummary(null, Collections.emptyList());

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getSubmittedBy() {
		return submittedBy;
	}

	public void setSubmittedBy(String submittedBy) {
		this.submittedBy = submittedBy;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	@JsonIgnore
	public StatusPresentationModel getStatusPresentation() {
		var snapshot = executionSummary.codeSnapshot();
		if (snapshot == null && !executionSummary.scanners().isEmpty()) {
			return StatusPresentationModel.from(com.tracelink.appsec.watchtower.core.scan.presentation.ScanAssessment.ofExecutions(
					ScanStatus.toStatus(status), executionSummary.scanners(), List.of()));
		}
		return StatusPresentationModel.from(com.tracelink.appsec.watchtower.core.scan.presentation.ScanAssessment.of(ScanStatus.toStatus(status), snapshot, List.of(), com.tracelink.appsec.watchtower.core.scan.presentation.ScanAssessment.failureReasons(executionSummary.scanners())));
	}

	/** The failure message without the server's working folders (also in the REST response). */
	public String getErrorMessage() {
		return ScanFailure.withoutServerPaths(error);
	}

	/** Why the scan failed, in plain words, or null when it did not fail. */
	@JsonIgnore
	public ScanFailure getFailure() {
		return ScanFailure.of(error);
	}

	/** The report's scanner tiles, the same as Home's Scanners column. */
	@JsonIgnore
	public ScannerBadge.Summary getScannerTiles() {
		return ScannerBadge.from(
				executionSummary.scanners(), null);
	}

	public void setErrorMessage(String error) {
		this.error = error;
	}

	public String getTicket() {
		return ticket;
	}

	public void setTicket(String ticket) {
		this.ticket = ticket;
	}

	public String getRuleset() {
		return ruleset;
	}

	public void setRuleset(String ruleset) {
		this.ruleset = ruleset;
	}

	public LocalDateTime getSubmitDate() {
		return submitDate;
	}

	public void setSubmitDate(LocalDateTime submitDate) {
		this.submitDate = submitDate;
	}

	public long getSubmitDateMillis() {
		return com.tracelink.appsec.watchtower.core.ui.ServerTime.toEpochMillis(submitDate);
	}

	public LocalDateTime getEndDate() {
		return endDate;
	}

	public void setEndDate(LocalDateTime endDate) {
		this.endDate = endDate;
	}

	public long getEndDateMillis() {
		return com.tracelink.appsec.watchtower.core.ui.ServerTime.toEpochMillis(endDate);
	}

	/** Submitted to finished, in the same format as every other scan list. */
	@JsonIgnore
	public String getDurationText() {
		return getEndDateMillis() > 0
				? com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem.formatDuration(
						getSubmitDateMillis(), getEndDateMillis())
				: "Not finished";
	}

	public int getViolationsFound() {
		return violations == null ? 0 : violations.size();
	}

	public List<UploadScanResultViolation> getViolations() {
		return violations;
	}

	public void setViolations(List<UploadScanResultViolation> violations) {
		this.violations = violations;
	}

	public ScanExecutionSummary getExecutionSummary() { return executionSummary; }

	public void setExecutionSummary(ScanExecutionSummary value) {
		this.executionSummary = value == null
				? new ScanExecutionSummary(null, Collections.emptyList()) : value;
	}


}
