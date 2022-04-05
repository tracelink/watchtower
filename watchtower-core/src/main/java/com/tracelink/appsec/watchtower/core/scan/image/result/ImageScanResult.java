package com.tracelink.appsec.watchtower.core.scan.image.result;

import java.util.ArrayList;
import java.util.List;

public class ImageScanResult {
	private String coordinates;

	private String ruleset;

	private String apiLabel;

	private long submitDate;

	private String status;

	private List<ImageScanResultViolation> violations = new ArrayList<>();

	public String getCoordinates() {
		return coordinates;
	}

	public void setCoordinates(String coordinates) {
		this.coordinates = coordinates;
	}

	public void setCoordinates(String registry, String image, String tag) {
		this.coordinates = registry + "/" + image + ":" + tag;
	}

	public String getRuleset() {
		return ruleset;
	}

	public void setRuleset(String ruleset) {
		this.ruleset = ruleset;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public long getSubmitDate() {
		return submitDate;
	}

	public void setSubmitDate(long submitDate) {
		this.submitDate = submitDate;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public List<ImageScanResultViolation> getViolations() {
		return violations;
	}

	public void setViolations(List<ImageScanResultViolation> violations) {
		this.violations = violations;
	}

	public void setErrorMessage(String string) {
		// TODO Auto-generated method stub

	}



}
