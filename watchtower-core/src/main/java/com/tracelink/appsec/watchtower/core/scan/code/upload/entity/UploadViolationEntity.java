package com.tracelink.appsec.watchtower.core.scan.code.upload.entity;

import java.nio.file.Path;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.code.AbstractCodeScanViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

/**
 * Violation Entity class for Uploads with join to {@linkplain UploadScanEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "upload_violations")
public class UploadViolationEntity extends
		AbstractCodeScanViolationEntity<UploadScanEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "scan_entity_id", nullable = false)
	private UploadScanEntity scan;

	public UploadViolationEntity() {
		super();
	}

	public UploadViolationEntity(CodeScanViolation sv, Path workingDirectory) {
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
