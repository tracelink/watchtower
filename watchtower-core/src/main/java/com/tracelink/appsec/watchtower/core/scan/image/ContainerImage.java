package com.tracelink.appsec.watchtower.core.scan.image;

public class ContainerImage {

	private String apiLabel;

	private String repository;

	private String imageName;

	private String tagName;

	public ContainerImage(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public String getRepository() {
		return repository;
	}

	public void setRepository(String repository) {
		this.repository = repository;
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
}
