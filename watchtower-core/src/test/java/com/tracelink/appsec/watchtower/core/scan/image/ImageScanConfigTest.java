package com.tracelink.appsec.watchtower.core.scan.image;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ImageScanConfigTest {
	@Test
	public void testDAO() {
		ImageSecurityReport securityReport = new ImageSecurityReport(new ImageScan());
		ImageScanConfig config = new ImageScanConfig();
		config.setSecurityReport(securityReport);
		Assertions.assertEquals(securityReport, config.getSecurityReport());
	}
}
