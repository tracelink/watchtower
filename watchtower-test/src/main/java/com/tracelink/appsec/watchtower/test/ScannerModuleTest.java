package com.tracelink.appsec.watchtower.test;

import java.util.function.Consumer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.AbstractModule;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanConfig;

/**
 * An encompassing test suite for Scanner Modules. This exercises all basic class contracts for all
 * objects required to be implemented by the Scanner Module
 *
 * @author csmith
 */
public abstract class ScannerModuleTest {

	private ScannerModuleTestBuilder scannerTester;
	private AbstractModule moduleUnderTest;

	/**
	 * Construct a Scanner Module for this test
	 * 
	 * @return an implementation of {@linkplain AbstractModule} to test
	 */
	protected abstract AbstractModule buildScannerModule();

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
		AbstractTestScanConfiguration testScan = scannerTester.getTestScanConfiguration();
		Assumptions.assumeFalse(testScan == null);

		String resource = testScan.getResourceFile();
		RulesetDto ruleset = testScan.getRuleset();
		Consumer<ScanReport> assertClause = testScan.getAssertClause();
		Assertions.assertNotNull(resource, "Misconfigured TestConfig: Missing Resource File");
		Assertions.assertNotNull(ruleset, "Misconfigured TestConfig: Missing Ruleset");
		Assertions.assertNotNull(assertClause, "Misconfigured TestConfig: Missing Asssertions");

		AbstractScanConfig config = testScan.getScanConfig();
		IScanner scanner = moduleUnderTest.getScanner();
		ScanReport report = scanner.scan(config);
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
