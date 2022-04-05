package com.tracelink.appsec.watchtower.core.scan.image.entity;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractViolationEntity;

@Entity
@Table(name = "image_violations")
public class ImageViolationEntity extends AbstractViolationEntity<ImageScanEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "scan_entity_id", nullable = false)
	private ImageScanEntity scan;

	@Override
	public ImageScanEntity getScan() {
		return scan;
	}

	@Override
	public void setScan(ImageScanEntity scan) {
		this.scan = scan;
	}

}
