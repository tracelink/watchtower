package com.tracelink.appsec.watchtower.core.scan.image.ecr.entity;

import java.util.List;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;

public class EcrScanEntity extends AbstractScanEntity<EcrContainerEntity, EcrViolationEntity> {

	@Override
	public EcrContainerEntity getContainer() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setContainer(EcrContainerEntity container) {
		// TODO Auto-generated method stub

	}

	@Override
	public List<EcrViolationEntity> getViolations() {
		// TODO Auto-generated method stub
		return null;
	}

}
