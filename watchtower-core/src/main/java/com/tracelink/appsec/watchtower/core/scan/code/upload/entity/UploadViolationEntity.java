package com.tracelink.appsec.watchtower.core.scan.code.upload.entity;

import java.nio.file.Path;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.report.ScanViolation;
import com.tracelink.appsec.watchtower.core.scan.AbstractViolationEntity;

/**
 * Violation Entity class for Uploads with join to {@linkplain UploadScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "upload_violations")
public class UploadViolationEntity extends
		AbstractViolationEntity<UploadScanEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "scan_entity_id", nullable = false)
	private UploadScanEntity scan;

	public UploadViolationEntity() {
		super();
	}

	public UploadViolationEntity(ScanViolation sv, Path workingDirectory) {
		super(sv, workingDirectory);
	}

	@Override
	public UploadScanEntity getScan() {
		return scan;
	}

	@Override
	public void setScan(UploadScanEntity scan) {
		this.scan = scan;
	}
}
