package com.tracelink.appsec.watchtower.core.scan.image.entity;

import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;

/**
 * Container Entity class for Uploads with reverse join to {@linkplain ImageScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "image_container")
public class ImageScanContainerEntity extends AbstractScanContainerEntity<ImageScanEntity> {

	@Column(name = "api_label")
	private String apiLabel;

	@Column(name = "registry_name")
	private String registryName;

	@Column(name = "image_name")
	private String imageName;

	@Column(name = "tag_name")
	private String tagName;

	@OneToMany(fetch = FetchType.EAGER, mappedBy = "container", cascade = CascadeType.MERGE)
	@OrderBy(value = "end_date DESC")
	private List<ImageScanEntity> scans;


	public ImageScanContainerEntity(ImageScan scan) {
		setApiLabel(scan.getApiLabel());
		setRegistryName(scan.getRegistryName());
		setImageName(scan.getImageName());
		setTagName(scan.getTagName());
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

	@Override
	public List<ImageScanEntity> getScans() {
		return scans;
	}
}
