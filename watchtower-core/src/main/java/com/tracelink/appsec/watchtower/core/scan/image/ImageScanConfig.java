package com.tracelink.appsec.watchtower.core.scan.image;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanConfig;

public class ImageScanConfig extends AbstractScanConfig {
	private ImageSecurityReport securityReport;

	public void setSecurityReport(ImageSecurityReport securityReport) {
		this.securityReport = securityReport;
	}

	public ImageSecurityReport getSecurityReport() {
		return securityReport;
	}



}
