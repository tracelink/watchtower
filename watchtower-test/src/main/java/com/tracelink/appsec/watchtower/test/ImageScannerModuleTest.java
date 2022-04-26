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
 * An encompassing test suite for Scanner Modules. This exercises all basic class contracts for all
 * objects required to be implemented by the Scanner Module
 *
 * @author csmith
 */
public abstract class ImageScannerModuleTest
		extends ScannerModuleTest<AbstractImageScanModule, ImageScanReport, ImageSecurityReport> {

	@Test
	public void testScan() throws Exception {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.SCANNER));
		TestScanConfiguration<ImageScanReport, ImageSecurityReport> testScan =
				scannerTester.getTestScanConfiguration();
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

		IImageScanner scanner = moduleUnderTest.getScanner();
		ImageScanReport report = scanner.scan(config);
		Assertions.assertNotNull(report);
		assertClause.accept(report);
	}
}
