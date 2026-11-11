package com.tracelink.appsec.module.betterleaks;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.betterleaks.engine.BetterleaksEngine;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.module.betterleaks.rules.BetterleaksProvidedRules;
import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.test.CodeScannerModuleTest;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder;

public class BetterleaksModuleTest extends CodeScannerModuleTest {

	/** Synthetic, split so that no secrets scanner flags this source file. */
	private static final String FAKE_PAT = "ghp_" + "Xa9Bc3De5Fg7Hi1Jk3Lm5No7Pq9Rs1Tu3Vw5";

	@Override
	protected AbstractCodeScanModule buildScannerModule() {
		BetterleaksModule module = new BetterleaksModule();
		module.setRuleDesigner(new com.tracelink.appsec.module.betterleaks.designer.BetterleaksRuleDesigner(
				new com.tracelink.appsec.module.betterleaks.service.BetterleaksRuleTester()));
		return module;
	}

	@Override
	protected void configurePluginTester(
			ScannerModuleTestBuilder<CodeScanReport, String> testPlan) {
		testPlan.withMigration("db/betterleaks").withName(BetterleaksModule.MODULE_NAME)
				.withSchemaName("betterleaks_schema_history")
				.withSupportedRuleClass(BetterleaksProvidedRuleDto.class,
						com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto.class)
				.withRuleSupplier(() -> BetterleaksProvidedRules.load().rules().get(0));
	}

	/**
	 * Replaces the harness's resource-file scan: a committed fixture would put a matchable token
	 * in the repository, so the fixture is written at run time instead.
	 */
	@Override
	@Test
	@Tag("requires-binary")
	public void testScan() throws Exception {
		Assumptions.assumeTrue(new BetterleaksEngine().isAvailable(),
				"betterleaks binary not installed");
		Path workingDirectory = Files.createTempDirectory("betterleaks-module-test");
		Files.createDirectories(workingDirectory.resolve("test"));
		Files.writeString(workingDirectory.resolve("test/Fixture.java"),
				"class Fixture {\n  String token = \"" + FAKE_PAT + "\";\n}\n");
		RulesetDto ruleset = BetterleaksProvidedRules.load().toDefaultRuleset();
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);
		config.setWorkingDirectory(workingDirectory);

		CodeScanReport report = getModuleUnderTest().getScanner().scan(config);

		Assertions.assertEquals(0, report.getErrors().size(), report.getErrors().toString());
		Assertions.assertEquals(1, report.getViolations().size());
		Assertions.assertEquals("Betterleaks: github-pat",
				report.getViolations().get(0).getViolationName());
		Assertions.assertEquals(2, report.getViolations().get(0).getLineNum());
	}

	@Test
	public void testAllowlistPageIsListedUnderConfigurationForItsPrivilege() {
		com.tracelink.appsec.watchtower.core.sidebar.SidebarService sidebar =
				new com.tracelink.appsec.watchtower.core.sidebar.SidebarService();
		BetterleaksModule module = new BetterleaksModule();
		module.setSidebarService(sidebar);

		module.registerSidebarLink();

		com.tracelink.appsec.watchtower.core.sidebar.SidebarLink link = sidebar.getMenuGroups()
				.stream().filter(group -> group.getGroupName().equals("Configuration"))
				.flatMap(group -> group.getLinks().stream())
				.filter(candidate -> BetterleaksModule.ALLOWLIST_URL.equals(candidate.getUrl()))
				.findFirst().orElseThrow();
		Assertions.assertEquals(
				"hasAuthority('" + BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME + "')",
				link.getAuthorizationExpression());
	}

	@Test
	public void testModuleDeclaresItsPrivilegesAndDefaultRuleset() {
		BetterleaksModule module = new BetterleaksModule();

		Assertions.assertEquals(Set.of(BetterleaksModule.RULE_EDITOR_PRIVILEGE_NAME,
				BetterleaksModule.RULE_DESIGNER_PRIVILEGE_NAME,
				BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME,
				BetterleaksModule.VERIFY_PRIVILEGE_NAME),
				Set.copyOf(module.getModulePrivileges().stream().map(p -> p.getName()).toList()));
		Assertions.assertEquals(1, module.getProvidedRulesets().size());
		Assertions.assertEquals(BetterleaksProvidedRules.DEFAULT_RULESET_NAME,
				module.getProvidedRulesets().get(0).getName());
	}
}
