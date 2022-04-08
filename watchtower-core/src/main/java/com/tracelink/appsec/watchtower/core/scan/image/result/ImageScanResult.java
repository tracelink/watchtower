package com.tracelink.appsec.watchtower.core.scan.image.result;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class ImageScanResult {
	private String registryName;
	private String imageName;
	private String tagName;
	private LocalDateTime submitDate;
	private String status;
	private String errorMessage;
	private LocalDateTime endDate;
	private List<ImageScanResultViolation> violations = new ArrayList<>();

	public String getRegistryName() {
		return registryName;
	}

	public void setRegistryName(String registryName) {
		this.registryName = registryName;
	}

	public String getImageName() {
		return imageName;
	}

	public void setImageName(String imageName) {
		this.imageName = imageName;
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
