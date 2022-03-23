package com.tracelink.appsec.watchtower.core.scan.api.image.ecr;

public class EcrImage {

	private String accountId;

	private String repository;

	private String imageName;

	private String tagName;

	public String getAccountId() {
		return accountId;
	}

	public void setAccountId(String accountId) {
		this.accountId = accountId;
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
