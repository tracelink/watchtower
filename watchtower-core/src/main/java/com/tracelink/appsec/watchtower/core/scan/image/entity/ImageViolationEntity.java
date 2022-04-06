package com.tracelink.appsec.watchtower.core.scan.image.entity;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanViolationEntity;

/**
 * Violation Entity class for Uploads with join to {@linkplain ImageScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "upload_violations")
public class ImageViolationEntity extends
		AbstractScanViolationEntity<ImageScanEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "scan_entity_id", nullable = false)
	private ImageScanEntity scan;

	@OneToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "advisory_id", referencedColumnName = "advisory_id")
	private AdvisoryEntity advisory;

	public ImageViolationEntity() {
		super();
	}

	@Override
	public ImageScanEntity getScan() {
		return scan;
	}

	@Override
	public void setScan(ImageScanEntity scan) {
		this.scan = scan;
	}
}
