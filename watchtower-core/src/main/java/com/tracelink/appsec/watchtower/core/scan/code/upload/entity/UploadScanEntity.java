package com.tracelink.appsec.watchtower.core.scan.code.upload.entity;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;

/**
 * Scan Entity class for Uploads with join to {@linkplain UploadScanContainerEntity} and reverse
 * join to {@linkplain UploadViolationEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "upload_scans")
public class UploadScanEntity
		extends AbstractScanEntity<UploadScanContainerEntity, UploadViolationEntity> {

	@OneToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "container_id", nullable = false)
	private UploadScanContainerEntity container;

	@OneToMany(fetch = FetchType.EAGER, mappedBy = "scan")
	private List<UploadViolationEntity> violations;

	@Override
	public UploadScanContainerEntity getContainer() {
		return container;
	}

	@Override
	public void setContainer(UploadScanContainerEntity container) {
		this.container = container;
	}

	@Override
	public List<UploadViolationEntity> getViolations() {
		return violations;
	}

}
