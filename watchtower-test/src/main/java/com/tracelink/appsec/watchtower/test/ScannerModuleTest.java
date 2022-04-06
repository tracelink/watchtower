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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder.TestScanConfiguration;

/**
 * An encompassing test suite for Scanner Modules. This exercises all basic class contracts for all
 * objects required to be implemented by the Scanner Module
 *
 * @author csmith
 */
public abstract class ScannerModuleTest {

	private ScannerModuleTestBuilder scannerTester;
	private AbstractCodeScanModule moduleUnderTest;

	/**
	 * Construct a Scanner Module for this test
	 * 
	 * @return an implementation of {@linkplain AbstractCodeScanModule} to test
	 */
	protected abstract AbstractCodeScanModule buildScannerModule();

	/**
	 * Configuration method to make the {@linkplain ScannerModuleTestBuilder} work for the Scanner
	 * Module under test
	 * 
	 * @param testPlan a {@linkplain ScannerModuleTestBuilder} to configure
	 */
	protected abstract void configurePluginTester(ScannerModuleTestBuilder testPlan);

	private ScannerModuleTestBuilder createTestPlanForModule() {
		ScannerModuleTestBuilder smtb = new ScannerModuleTestBuilder();
		scannerTester = smtb;
		return smtb;
	}

	@BeforeEach
	public void setupTestHarness() {
		moduleUnderTest = buildScannerModule();
		scannerTester = createTestPlanForModule();
		configurePluginTester(scannerTester);
	}

	@Test
	public void testGetName() {
		Assertions.assertEquals(this.scannerTester.getName(), this.moduleUnderTest.getName());
	}

	@Test
	public void testSchemaName() {
		Assertions.assertEquals(this.scannerTester.getSchemaName(),
				this.moduleUnderTest.getSchemaHistoryTable());
	}

	@Test
	public void testMigrationLocation() {
		Assertions.assertEquals(this.scannerTester.getMigration(),
				this.moduleUnderTest.getMigrationsLocation());
	}

	@Test
	public void testSupportedRules() {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.SCANNER));
		Assertions.assertEquals(this.scannerTester.getSupportedRuleClass(),
				this.moduleUnderTest.getScanner().getSupportedRuleClass());

		RuleDto rule = this.scannerTester.getRuleSupplier().get();
		Assertions.assertEquals(rule.getClass(),
				this.moduleUnderTest.getScanner().getSupportedRuleClass());
	}

	@Test
	public void testScannerExists() {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.SCANNER));
		Assertions.assertNotNull(this.moduleUnderTest.getScanner());
	}

	@Test
	public void testScan() throws Exception {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.SCANNER));
		TestScanConfiguration testScan = scannerTester.getTestScanConfiguration();
		Assumptions.assumeFalse(testScan == null);

		String resource = testScan.getResourceFile();
		RulesetDto ruleset = testScan.getRuleset();
		Consumer<CodeScanReport> assertClause = testScan.getAssertClause();
		Assertions.assertNotNull(resource, "Misconfigured TestConfig: Missing Resource File");
		Assertions.assertNotNull(ruleset, "Misconfigured TestConfig: Missing Ruleset");
		Assertions.assertNotNull(assertClause, "Misconfigured TestConfig: Missing Asssertions");

		Path testDir = Files.createTempDirectory(null);
		Path testFile = testDir.resolve(Paths.get(resource).getFileName());

		try (InputStream is =
				getClass().getResourceAsStream(testScan.getResourceFile());
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

	@Test
	public void testDesignerExists() {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.DESIGNER));
		Assertions.assertNotNull(this.moduleUnderTest.getRuleDesigner());
	}

	@Test
	public void testDesignerMAVExists() {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.DESIGNER));
		Assertions.assertNotNull(
				this.moduleUnderTest.getRuleDesigner().getRuleDesignerModelAndView());
	}

	@Test
	public void testEditorExists() {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.EDITOR));
		Assertions.assertNotNull(this.moduleUnderTest.getRuleEditor());
	}

	@Test
	public void testEditorMAVExists() {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.EDITOR));
		Assertions.assertNotNull(this.moduleUnderTest.getRuleEditor().getRuleEditModelAndView(
				this.scannerTester.getRuleSupplier().get()));
	}

	@Test
	public void testProvidedRulesExist() {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.PROVIDED_RULES));
		Assertions.assertNotNull(this.moduleUnderTest.getProvidedRulesets());
		Assertions.assertNotEquals(0, this.moduleUnderTest.getProvidedRulesets().size());
	}
}
