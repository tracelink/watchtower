package com.tracelink.appsec.watchtower.core.scan.image;

public class ImageScan {

	private String apiLabel;

	private String imageName;

	private String imageTag;

	public ImageScan(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public String getImageName() {
		return imageName;
	}

	public void setImageName(String imageName) {
		this.imageName = imageName;
	}

	public String getImageTag() {
		return imageTag;
	}

	public void setImageTag(String imageTag) {
		this.imageTag = imageTag;
	}

	public void parseScanFromWebhook(String imageScan) {
		// TODO
	}

}
