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
 */
@Entity
@Table(name = "image_container")
public class ImageScanContainerEntity extends AbstractScanContainerEntity<ImageScanEntity> {

	@Column(name = "api_label")
	private String apiLabel;

	@Column(name = "repository_name")
	private String repositoryName;

	@Column(name = "tag_name")
	private String tagName;

	@OneToMany(fetch = FetchType.EAGER, mappedBy = "container", cascade = CascadeType.MERGE)
	@OrderBy(value = "end_date DESC")
	private List<ImageScanEntity> scans;

	public ImageScanContainerEntity() {

	}

	public ImageScanContainerEntity(ImageScan scan) {
		setApiLabel(scan.getApiLabel());
		setRepositoryName(scan.getRepository());
		setTagName(scan.getTag());
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

	@Override
	public List<ImageScanEntity> getScans() {
		return scans;
	}
}
