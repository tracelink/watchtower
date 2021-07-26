package com.tracelink.appsec.module.checkov;

import java.util.List;
import java.util.stream.Collectors;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeAll;

import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.module.AbstractModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.test.ScannerModuleTest;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder.TestScanConfiguration;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestOption;

public class CheckovModuleTest extends ScannerModuleTest {

	private static CheckovEngine engine;

	@BeforeAll
	public static void beforeClass() {
		engine = new CheckovEngine();
	}

	@Override
	protected AbstractModule buildScannerModule() {
		return new CheckovModule(engine);
	}

	@Override
	protected void configurePluginTester(ScannerModuleTestBuilder testPlan) {
		List<CheckovProvidedRuleDto> coreRules = engine.getCoreRules();
		testPlan.withMigration("db/checkov").withName("Checkov")
				.withRuleSupplier(() -> {
					// CKV_AWS_9 only has 1 implementation IaC
					CheckovProvidedRuleDto rule =
							coreRules.stream().filter(r -> r.getName().equals("CKV_AWS_9"))
									.findFirst().get();
					rule.setPriority(RulePriority.HIGH);
					return rule;
				}).withSchemaName("checkov_schema_history")
				.withSupportedRuleClass(CheckovProvidedRuleDto.class)
				.andIgnoreTestOption(ScannerModuleTestOption.DESIGNER)
				.withTestScanConfigurationBuilder(
						new TestScanConfiguration()
								.withTargetResourceFile("/terraformtest/terraform_iam.tf")
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
