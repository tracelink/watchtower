package com.tracelink.appsec.watchtower.core.scan.image.entity;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;

/**
 * Scan Entity class for Uploads with join to {@linkplain ImageScanContainerEntity} and reverse join
 * to {@linkplain ImageViolationEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "image_scan")
public class ImageScanEntity
		extends AbstractScanEntity<ImageScanContainerEntity, ImageViolationEntity> {

	@OneToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "container_id", nullable = false)
	private ImageScanContainerEntity container;

	@ManyToMany(fetch = FetchType.EAGER, mappedBy = "scan")
	private List<ImageViolationEntity> violations;

	@Override
	public ImageScanContainerEntity getContainer() {
		return container;
	}

	@Override
	public void setContainer(ImageScanContainerEntity container) {
		this.container = container;
	}

	@Override
	public List<ImageViolationEntity> getViolations() {
		return violations;
	}

	public void setViolations(List<ImageViolationEntity> violations) {
		this.violations = violations;
	}

}
