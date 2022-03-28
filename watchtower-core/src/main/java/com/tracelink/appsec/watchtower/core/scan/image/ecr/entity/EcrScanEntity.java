package com.tracelink.appsec.watchtower.core.scan.image.ecr.entity;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;

@Entity
@Table(name = "ecr_scans")
public class EcrScanEntity extends AbstractScanEntity<EcrContainerEntity, EcrViolationEntity> {

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "container_id", nullable = false)
	private EcrContainerEntity container;

	@OneToMany(fetch = FetchType.EAGER, mappedBy = "scan")
	private List<EcrViolationEntity> violations;

	@Override
	public EcrContainerEntity getContainer() {
		return container;
	}

	@Override
	public void setContainer(EcrContainerEntity container) {
		this.container = container;
	}

	@Override
	public List<EcrViolationEntity> getViolations() {
		return violations;
	}

}
