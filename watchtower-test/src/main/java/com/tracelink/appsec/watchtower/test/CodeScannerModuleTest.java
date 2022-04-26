package com.tracelink.appsec.watchtower.test;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.function.Consumer;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

/**
 * An encompassing test suite for Scanner Modules. This exercises all basic class contracts for all
 * objects required to be implemented by the Scanner Module
 *
 * @author csmith
 */
public abstract class CodeScannerModuleTest
		extends ScannerModuleTest<AbstractCodeScanModule, CodeScanReport, String> {

	@Test
	public void testScan() throws Exception {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.SCANNER));
		TestScanConfiguration<CodeScanReport, String> testScan =
				scannerTester.getTestScanConfiguration();
		Assumptions.assumeFalse(testScan == null);

		String resource = testScan.getScannerTarget();
		RulesetDto ruleset = testScan.getRuleset();
		Consumer<CodeScanReport> assertClause = testScan.getAssertClause();
		Assertions.assertNotNull(resource, "Misconfigured TestConfig: Missing Resource File");
		Assertions.assertNotNull(ruleset, "Misconfigured TestConfig: Missing Ruleset");
		Assertions.assertNotNull(assertClause, "Misconfigured TestConfig: Missing Asssertions");

		Path testDir = Files.createTempDirectory(null);
		Path testFile = testDir.resolve(Paths.get(resource).getFileName());

		try (InputStream is =
				getClass().getResourceAsStream(testScan.getScannerTarget());
				FileOutputStream fos = new FileOutputStream(testFile.toFile())) {
			IOUtils.copy(is, fos);
		}
		Assertions.assertTrue(testFile.toFile().exists());
		CodeScanConfig config = new CodeScanConfig();
		config.setBenchmarkEnabled(false);
		config.setDebugEnabled(false);
		config.setRuleset(ruleset);
		config.setThreads(0);
		config.setWorkingDirectory(testDir);

		ICodeScanner scanner = moduleUnderTest.getScanner();
		CodeScanReport report = scanner.scan(config);
		Assertions.assertNotNull(report);
		assertClause.accept(report);
	}
}
