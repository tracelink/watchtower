package com.tracelink.appsec.watchtower.core.scan.image.entity;

import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanContainer;

@Entity
@Table(name = "image_container")
public class ImageContainerEntity extends AbstractScanContainer<ImageScanEntity> {

	@Column(name = "api_label")
	private String apiLabel;

	@Column(name = "ruleset")
	private String ruleSetName;

	@Column(name = "registry_name")
	private String registryName;

	@Column(name = "image_name")
	private String imageName;

	@Column(name = "tag_name")
	private String tagName;

	@OneToMany(fetch = FetchType.EAGER, mappedBy = "container", cascade = CascadeType.MERGE)
	@OrderBy(value = "end_date DESC")
	private List<ImageScanEntity> scans;

	@Override
	public List<ImageScanEntity> getScans() {
		return scans;
	}

	public ImageScanEntity getLatestScan() {
		return getScans().isEmpty() ? null : getScans().get(0);
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

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

	public String getRuleSetName() {
		return ruleSetName;
	}

	public void setRuleSetName(String ruleSetName) {
		this.ruleSetName = ruleSetName;
	}

}
