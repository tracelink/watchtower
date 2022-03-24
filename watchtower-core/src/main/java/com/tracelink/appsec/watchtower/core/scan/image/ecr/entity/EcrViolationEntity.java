package com.tracelink.appsec.watchtower.core.scan.image.ecr.entity;

import com.tracelink.appsec.watchtower.core.scan.AbstractViolationEntity;

public class EcrViolationEntity extends AbstractViolationEntity<EcrScanEntity> {

	@Override
	public void setBlocking(boolean b) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isBlocking() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public EcrScanEntity getScan() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setScan(EcrScanEntity scan) {
		// TODO Auto-generated method stub

	}

}
