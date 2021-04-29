package com.tracelink.appsec.watchtower.core.scan.upload.result;

import java.time.LocalDateTime;
import java.util.List;

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

	public String getErrorMessage() {
		return error;
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

	public LocalDateTime getEndDate() {
		return endDate;
	}

	public void setEndDate(LocalDateTime endDate) {
		this.endDate = endDate;
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


}
