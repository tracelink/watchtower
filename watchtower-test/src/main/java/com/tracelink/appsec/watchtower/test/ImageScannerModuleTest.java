package com.tracelink.appsec.watchtower.test;

import java.util.function.Consumer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.AbstractImageScanModule;
import com.tracelink.appsec.watchtower.core.module.scanner.IImageScanner;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanReport;

/**
 * Test suite configuration for Image Scanners
 * 
 * @author csmith
 */
public abstract class ImageScannerModuleTest
		extends ScannerModuleTest<AbstractImageScanModule, ImageScanReport, ImageSecurityReport> {

	@Test
	public void testScan() throws Exception {
		Assumptions.assumeFalse(
				getScannerTester().getIgnoredOptions().contains(ScannerModuleTestOption.SCANNER));
		TestScanConfiguration<ImageScanReport, ImageSecurityReport> testScan =
				getScannerTester().getTestScanConfiguration();
		Assumptions.assumeFalse(testScan == null);

		ImageSecurityReport resource = testScan.getScannerTarget();
		RulesetDto ruleset = testScan.getRuleset();
		Consumer<ImageScanReport> assertClause = testScan.getAssertClause();
		Assertions.assertNotNull(resource, "Misconfigured TestConfig: Missing Scanner Target");
		Assertions.assertNotNull(ruleset, "Misconfigured TestConfig: Missing Ruleset");
		Assertions.assertNotNull(assertClause, "Misconfigured TestConfig: Missing Assertions");

		ImageScanConfig config = new ImageScanConfig();
		config.setBenchmarkEnabled(false);
		config.setRuleset(ruleset);
		config.setSecurityReport(resource);

		IImageScanner scanner = getModuleUnderTest().getScanner();
		ImageScanReport report = scanner.scan(config);
		Assertions.assertNotNull(report);
		assertClause.accept(report);
	}
}
