package com.tracelink.appsec.watchtower.core.scan.image;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrImageScan;

public class ImageScanConfigTest {
	@Test
	public void testDAO() {
		ImageSecurityReport securityReport = new ImageSecurityReport(new EcrImageScan(""));
		ImageScanConfig config = new ImageScanConfig();
		config.setSecurityReport(securityReport);
		Assertions.assertEquals(securityReport, config.getSecurityReport());
	}
}
