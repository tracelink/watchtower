package com.tracelink.appsec.watchtower.test;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.AbstractModule;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanReport;

/**
 * An encompassing test suite for Scanner Modules. This exercises all basic class contracts for all
 * objects required to be implemented by the Scanner Module
 *
 * @author csmith
 * @param <M> The type of {@linkplain AbstractModule} under test
 * @param <R> The type of {@linkplain AbstractScanReport} used in this tester
 * @param <I> The Scanner Target (item scanned) type used in this tester
 */
public abstract class ScannerModuleTest<M extends AbstractModule<?>, R extends AbstractScanReport, I> {
	private ScannerModuleTestBuilder<R, I> scannerTester;
	private M moduleUnderTest;

	/**
	 * Construct a Scanner Module for this test
	 * 
	 * @return an implementation of {@linkplain AbstractModule} to test
	 */
	protected abstract M buildScannerModule();

	/**
	 * Configuration method to make the {@linkplain ScannerModuleTestBuilder} work for the Scanner
	 * Module under test
	 * 
	 * @param testPlan a {@linkplain ScannerModuleTestBuilder} to configure
	 */
	protected abstract void configurePluginTester(
			ScannerModuleTestBuilder<R, I> testPlan);


	private ScannerModuleTestBuilder<R, I> createTestPlanForModule() {
		ScannerModuleTestBuilder<R, I> smtb =
				new ScannerModuleTestBuilder<>();
		scannerTester = smtb;
		return smtb;
	}

	@BeforeEach
	public void setupTestHarness() {
		moduleUnderTest = buildScannerModule();
		scannerTester = createTestPlanForModule();
		configurePluginTester(scannerTester);
	}

	protected final ScannerModuleTestBuilder<R, I> getScannerTester() {
		return scannerTester;
	}

	protected final M getModuleUnderTest() {
		return moduleUnderTest;
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
				this.moduleUnderTest.getRuleDesigner().getDefaultRuleDesignerModelAndView());
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
		Assertions
				.assertNotNull(this.moduleUnderTest.getRuleEditor().getDefaultRuleEditModelAndView(
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
