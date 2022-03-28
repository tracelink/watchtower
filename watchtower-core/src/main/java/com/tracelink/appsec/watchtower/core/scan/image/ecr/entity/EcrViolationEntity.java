package com.tracelink.appsec.watchtower.core.scan.image.ecr.entity;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractViolationEntity;

@Entity
@Table(name = "ecr_violations")
public class EcrViolationEntity extends AbstractViolationEntity<EcrScanEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "scan_entity_id", nullable = false)
	private EcrScanEntity scan;

	@Override
	public EcrScanEntity getScan() {
		return scan;
	}

	@Override
	public void setScan(EcrScanEntity scan) {
		this.scan = scan;
	}

}
