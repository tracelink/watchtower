package com.tracelink.appsec.watchtower.core.scan.image.entity;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Transient;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanViolation;

/**
 * Violation Entity class for Uploads with join to {@linkplain ImageScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "upload_violations")
public class ImageViolationEntity
		extends AbstractScanViolationEntity<ImageScanEntity>
		implements Comparable<ImageViolationEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "scan_entity_id", nullable = false)
	private ImageScanEntity scan;

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "advisory_id", nullable = false)
	private AdvisoryEntity advisory;

	@Transient
	private boolean blocking;

	public ImageViolationEntity() {
		super();
	}

	public ImageViolationEntity(ImageScanViolation sv, AdvisoryEntity advisory) {
		setSeverity(sv.getSeverity());
		setViolationName(sv.getFindingName());
		setAdvisory(advisory);
	}

	@Override
	public ImageScanEntity getScan() {
		return scan;
	}

	@Override
	public void setScan(ImageScanEntity scan) {
		this.scan = scan;
	}

	public AdvisoryEntity getAdvisory() {
		return advisory;
	}

	public void setAdvisory(AdvisoryEntity advisory) {
		this.advisory = advisory;
	}

	public boolean isBlocking() {
		return blocking;
	}

	public void setBlocking(boolean blocking) {
		this.blocking = blocking;
	}

	@Override
	public int compareTo(ImageViolationEntity other) {
		return 0;
	}

}
