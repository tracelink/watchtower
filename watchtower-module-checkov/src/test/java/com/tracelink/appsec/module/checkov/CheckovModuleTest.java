package com.tracelink.appsec.module.checkov;

import java.util.List;
import java.util.stream.Collectors;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeAll;

import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.test.CodeScannerModuleTest;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestOption;
import com.tracelink.appsec.watchtower.test.TestScanConfiguration;

public class CheckovModuleTest extends CodeScannerModuleTest {

	private static CheckovEngine engine;

	@BeforeAll
	public static void beforeClass() {
		engine = new CheckovEngine();
	}

	@Override
	protected AbstractCodeScanModule buildScannerModule() {
		return new CheckovModule(engine);
	}

	@Override
	protected void configurePluginTester(
			ScannerModuleTestBuilder<CodeScanReport, String> testPlan) {
		List<CheckovProvidedRuleDto> coreRules = engine.getCoreRules();
		testPlan.withMigration("db/checkov").withName("Checkov")
				.withRuleSupplier(() -> {
					CheckovProvidedRuleDto rule = coreRules.get(0);
					rule.setPriority(RulePriority.HIGH);
					return rule;
				}).withSchemaName("checkov_schema_history")
				.withSupportedRuleClass(CheckovProvidedRuleDto.class)
				.andIgnoreTestOption(ScannerModuleTestOption.DESIGNER)
				.withTestScanConfigurationBuilder(
						new TestScanConfiguration<CodeScanReport, String>()
								.withScannerTarget("/terraformtest/terraform_iam.tf")
								.withRuleset(new RulesetDto() {
									{
										setName("testRuleset");
										setDescription("description");
										setRules(
												coreRules.stream()
														.peek(r -> r.setPriority(RulePriority.HIGH))
														.collect(Collectors.toSet()));
									}
								})
								.withAssertClause(report -> {
									MatcherAssert.assertThat(report.getErrors(),
											Matchers.hasSize(0));
									MatcherAssert.assertThat(report.getViolations(),
											Matchers.hasSize(7));
								}));
	}
}
