package com.tracelink.appsec.watchtower.core.scan.image;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanConfig;

public class ImageScanConfig extends AbstractScanConfig {
	private ImageScan imageScan;
	private ImageSecurityReport securityReport;

	public void setScan(ImageScan scan) {
		this.imageScan = scan;
	}

	public ImageScan getScan() {
		return imageScan;
	}

	public void setSecurityReport(ImageSecurityReport securityReport) {
		this.securityReport = securityReport;
	}

	public ImageSecurityReport getSecurityReport() {
		return securityReport;
	}



}
