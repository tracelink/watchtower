package com.tracelink.appsec.watchtower.core.scan.image;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanConfig;

public class ImageScanConfig extends AbstractScanConfig {
	private ImageSecurityReport report;

	public void setImageReport(ImageSecurityReport report) {
		this.report = report;
	}

	public ImageSecurityReport getImageReport() {
		return report;
	}

}
