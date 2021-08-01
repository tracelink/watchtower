package com.tracelink.appsec.watchtower.test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.function.Consumer;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.AbstractModule;
import com.tracelink.appsec.watchtower.core.module.interpreter.IRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.ScanConfig;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder.TestScanConfiguration;

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
		TestScanConfiguration testScan = scannerTester.getTestScanConfiguration();
		Assumptions.assumeFalse(testScan == null);

		String resource = testScan.getResourceFile();
		RulesetDto ruleset = testScan.getRuleset();
		Consumer<ScanReport> assertClause = testScan.getAssertClause();
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
		ScanConfig config = new ScanConfig();
		config.setBenchmarkEnabled(false);
		config.setDebugEnabled(false);
		config.setRuleset(ruleset);
		config.setThreads(0);
		config.setWorkingDirectory(testDir);

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
	@Disabled
	public void testImportExport() throws Exception {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.INTERPRETER));
		IRulesetInterpreter impex = this.moduleUnderTest.getInterpreter();
		Assertions.assertNotNull(impex);

		RulesetDto rulesetDto = new RulesetDto();
		rulesetDto.setName("test");
		rulesetDto.setDescription("test");
		rulesetDto.setDesignation(RulesetDesignation.SUPPORTING);
		rulesetDto.setRules(Collections.singleton(this.scannerTester.getRuleSupplier().get()));

		Path temp = Files.createTempFile(null, null);
		RulesetDto importedRuleset = null;
		try {
			try (InputStream is = impex.exportRuleset(rulesetDto);
					FileWriter fw = new FileWriter(temp.toFile())) {
				IOUtils.copy(is, fw, Charset.defaultCharset());
			}
			try (FileInputStream fis = new FileInputStream(temp.toFile())) {
				importedRuleset = impex.importRuleset(fis);
			}
		} finally {
			FileUtils.deleteQuietly(temp.toFile());
		}
		Assertions.assertNotNull(importedRuleset);
		MatcherAssert.assertThat(importedRuleset.getAllRules(),
				Matchers.hasSize(rulesetDto.getAllRules().size()));
		for (RuleDto impRule : importedRuleset.getAllRules()) {
			boolean found = false;
			for (RuleDto rule : rulesetDto.getAllRules()) {
				if (rule.getName().equals(impRule.getName())) {
					found = true;
					Assertions.assertEquals(impRule.getExternalUrl(), rule.getExternalUrl());
					Assertions.assertEquals(impRule.getMessage(), rule.getMessage());
					Assertions.assertEquals(impRule.getModule(), rule.getModule());
					Assertions.assertEquals(impRule.getPriority(), rule.getPriority());
				}
			}
			Assertions.assertTrue(found,
					"Could not find a matching rule after export/import for rule: "
							+ impRule.getName());
		}
	}

	@Test
	public void testExampleDownload() throws Exception {
		Assumptions.assumeFalse(
				scannerTester.getIgnoredOptions().contains(ScannerModuleTestOption.INTERPRETER));

		IRulesetInterpreter interpreter = this.moduleUnderTest.getInterpreter();
		Assertions.assertNotNull(interpreter);

		InputStream is = interpreter.exportExampleRuleset();
		Assertions.assertNotNull(is);
	}
}
