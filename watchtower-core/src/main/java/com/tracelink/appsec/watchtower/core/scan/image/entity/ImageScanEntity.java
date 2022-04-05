package com.tracelink.appsec.watchtower.core.scan.image.entity;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;

@Entity
@Table(name = "image_scans")
public class ImageScanEntity
		extends AbstractScanEntity<ImageContainerEntity, ImageViolationEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "container_id", nullable = false)
	private ImageContainerEntity container;

	@OneToMany(fetch = FetchType.EAGER, mappedBy = "scan")
	private List<ImageViolationEntity> violations;

	@Override
	public ImageContainerEntity getContainer() {
		return container;
	}

	@Override
	public void setContainer(ImageContainerEntity container) {
		this.container = container;
	}

	@Override
	public List<ImageViolationEntity> getViolations() {
		return violations;
	}


}
