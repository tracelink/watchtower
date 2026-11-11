package com.tracelink.appsec.module.betterleaks.scanner;

import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;

import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistEntry;
import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistProvider;
import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistScope;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksEngine;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksFinding;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksScanException;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCategory;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.module.scanner.ScanScope;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

public class BetterleaksScannerTest {

	@TempDir
	Path workingDirectory;

	private BetterleaksEngine engine;

	private BetterleaksScanner scanner;

	@BeforeEach
	public void setup() {
		engine = BDDMockito.mock(BetterleaksEngine.class);
		scanner = new BetterleaksScanner(engine);
	}

	static BetterleaksProvidedRuleDto rule(String betterleaksId, RulePriority priority) {
		BetterleaksProvidedRuleDto rule = new BetterleaksProvidedRuleDto();
		rule.setBetterleaksId(betterleaksId);
		rule.setName("Betterleaks: " + betterleaksId);
		rule.setMessage("Guidance for " + betterleaksId);
		rule.setExternalUrl("https://example.invalid/" + betterleaksId);
		rule.setPriority(priority);
		rule.setCategory(BetterleaksCategory.of(betterleaksId));
		rule.setConfidence("high");
		return rule;
	}

	private CodeScanConfig configWith(RuleDto... rules) {
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("pilot");
		ruleset.setRules(Set.of(rules));
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);
		config.setWorkingDirectory(workingDirectory);
		config.setRepositoryName("payments");
		return config;
	}

	private void givenEngineFinds(BetterleaksFinding... findings) throws Exception {
		BDDMockito.when(engine.scan(BDDMockito.any(), BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenReturn(List.of(findings));
	}

	@SuppressWarnings("unchecked")
	private Collection<String> enabledRuleIds() throws Exception {
		ArgumentCaptor<Collection<String>> ids = ArgumentCaptor.forClass(Collection.class);
		BDDMockito.verify(engine).scan(BDDMockito.eq(workingDirectory), ids.capture(),
				BDDMockito.any(), BDDMockito.any());
		return ids.getValue();
	}

	@Test
	public void testMapsEachFindingToAViolationAtItsRulesPriority() throws Exception {
		givenEngineFinds(new BetterleaksFinding("github-pat", "test/Fixture.java", 3));

		CodeScanReport report = scanner.scan(configWith(rule("github-pat", RulePriority.MEDIUM_LOW),
				rule("slack-bot-token", RulePriority.HIGH)));

		Assertions.assertEquals(List.of(), report.getErrors());
		Assertions.assertEquals(1, report.getViolations().size());
		CodeScanViolation violation = report.getViolations().get(0);
		Assertions.assertEquals("Betterleaks: github-pat", violation.getViolationName());
		// The ruleset owner's edited priority, not the category default.
		Assertions.assertEquals(RulePriority.MEDIUM_LOW, violation.getSeverity());
		Assertions.assertEquals(workingDirectory.resolve("test/Fixture.java").toString(),
				violation.getFileName());
		Assertions.assertEquals(3, violation.getLineNum());
		Assertions.assertEquals("Guidance for github-pat", violation.getMessage());
		Assertions.assertEquals(rule("github-pat", RulePriority.MEDIUM_LOW).getExecutionIdentity(),
				violation.getRuleIdentity());
	}

	@Test
	public void testRunsOnlyTheRulesetsBetterleaksRules() throws Exception {
		givenEngineFinds();

		scanner.scan(configWith(rule("github-pat", RulePriority.HIGH),
				rule("aws-access-token", RulePriority.HIGH), BDDMockito.mock(RuleDto.class)));

		MatcherAssert.assertThat(enabledRuleIds(),
				Matchers.containsInAnyOrder("github-pat", "aws-access-token"));
	}

	@Test
	public void testRuleOnlyAllowlistEntryDisablesThatRule() throws Exception {
		BetterleaksAllowlistEntry disableAws = new BetterleaksAllowlistEntry(
				BetterleaksAllowlistScope.REPO, "payments", null, "aws-access-token");
		BetterleaksAllowlistEntry fixtures = new BetterleaksAllowlistEntry(
				BetterleaksAllowlistScope.GLOBAL, null, "src/test/**", null);
		BetterleaksAllowlistProvider provider = repositoryName -> {
			Assertions.assertEquals("payments", repositoryName);
			return List.of(disableAws, fixtures);
		};
		scanner = new BetterleaksScanner(engine, provider, null);
		givenEngineFinds();

		scanner.scan(configWith(rule("github-pat", RulePriority.HIGH),
				rule("aws-access-token", RulePriority.HIGH)));

		@SuppressWarnings("unchecked")
		ArgumentCaptor<Collection<BetterleaksAllowlistEntry>> allowlist =
				ArgumentCaptor.forClass(Collection.class);
		BDDMockito.verify(engine).scan(BDDMockito.eq(workingDirectory),
				BDDMockito.eq(Set.of("github-pat")), allowlist.capture(), BDDMockito.any());
		MatcherAssert.assertThat(allowlist.getValue(), Matchers.contains(fixtures));
	}

	@Test
	public void testEveryRuleAllowlistedMeansNoScan() {
		scanner = new BetterleaksScanner(engine, repositoryName -> List.of(
				new BetterleaksAllowlistEntry(BetterleaksAllowlistScope.GLOBAL, null, null,
						"github-pat")), null);

		CodeScanReport report = scanner.scan(configWith(rule("github-pat", RulePriority.HIGH)));

		Assertions.assertEquals(List.of(), report.getErrors());
		BDDMockito.verifyNoInteractions(engine);
	}

	@Test
	public void testRelativeFindingPathIsResolvedAgainstTheWorkingDirectory() throws Exception {
		givenEngineFinds(new BetterleaksFinding("github-pat", "src/App.java", 1));

		CodeScanReport report = scanner.scan(configWith(rule("github-pat", RulePriority.HIGH)));

		Assertions.assertEquals(workingDirectory.resolve("src/App.java").toString(),
				report.getViolations().get(0).getFileName());
	}

	@Test
	public void testAFindingOutsideTheScannedDirectoryIsRejected() throws Exception {
		// Never expected from the binary; a guard in case the tree is ever populated differently.
		givenEngineFinds(new BetterleaksFinding("github-pat", "../../etc/passwd", 1),
				new BetterleaksFinding("github-pat", "src/App.java", 2));

		CodeScanReport report = scanner.scan(configWith(rule("github-pat", RulePriority.HIGH)));

		Assertions.assertEquals(1, report.getViolations().size());
		Assertions.assertEquals(2, report.getViolations().get(0).getLineNum());
		MatcherAssert.assertThat(report.getErrors().get(0).getErrorMessage(),
				Matchers.containsString("outside the scanned directory"));
	}

	@Test
	public void testEngineFailureFailsOpenWithAScanIncompleteError() throws Exception {
		BDDMockito.when(engine.scan(BDDMockito.any(), BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenThrow(new BetterleaksScanException(BetterleaksScanException.Reason.TIMEOUT,
						"betterleaks timed out after 120s"));

		CodeScanReport report = scanner.scan(configWith(rule("github-pat", RulePriority.HIGH)));

		Assertions.assertEquals(List.of(), report.getViolations());
		Assertions.assertEquals(1, report.getErrors().size());
		MatcherAssert.assertThat(report.getErrors().get(0).getErrorMessage(),
				Matchers.allOf(Matchers.containsString("Betterleaks scan incomplete"),
						Matchers.containsString("timed out")));
	}

	@Test
	public void testAllowlistLookupFailureFailsOpenToo() {
		scanner = new BetterleaksScanner(engine, repositoryName -> {
			throw new IllegalStateException("database down");
		}, null);

		CodeScanReport report = scanner.scan(configWith(rule("github-pat", RulePriority.HIGH)));

		MatcherAssert.assertThat(report.getErrors().get(0).getErrorMessage(),
				Matchers.containsString("Betterleaks scan incomplete"));
		BDDMockito.verifyNoInteractions(engine);
	}

	@Test
	public void testFindingForARuleOutsideTheRulesetIsReportedAsAnError() throws Exception {
		givenEngineFinds(new BetterleaksFinding("slack-bot-token", "src/App.java", 1));

		CodeScanReport report = scanner.scan(configWith(rule("github-pat", RulePriority.HIGH)));

		Assertions.assertEquals(List.of(), report.getViolations());
		MatcherAssert.assertThat(report.getErrors().get(0).getErrorMessage(),
				Matchers.containsString("slack-bot-token"));
	}

	@Test
	public void testRulesetWithoutBetterleaksRulesNeverRunsTheEngine() {
		CodeScanReport report = scanner.scan(configWith(BDDMockito.mock(RuleDto.class)));

		Assertions.assertEquals(List.of(), report.getViolations());
		BDDMockito.verifyNoInteractions(engine);
	}

	@Test
	public void testRecordsDurationFindingsAndFailureMetrics() throws Exception {
		SimpleMeterRegistry registry = new SimpleMeterRegistry();
		scanner = new BetterleaksScanner(engine, BetterleaksAllowlistProvider.NONE, registry);
		givenEngineFinds(new BetterleaksFinding("github-pat", "a.java", 1),
				new BetterleaksFinding("github-pat", "b.java", 2));

		scanner.scan(configWith(rule("github-pat", RulePriority.HIGH)));

		Assertions.assertEquals(2.0, registry.get(BetterleaksScanner.FINDINGS_METRIC)
				.tag("rule", "github-pat").counter().count());
		Assertions.assertEquals(1L, registry.get(BetterleaksScanner.DURATION_METRIC)
				.tag("outcome", "success").timer().count());

		BDDMockito.when(engine.scan(BDDMockito.any(), BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenThrow(new BetterleaksScanException(BetterleaksScanException.Reason.EXIT_CODE,
						"betterleaks failed with exit code 1"));
		scanner.scan(configWith(rule("github-pat", RulePriority.HIGH)));

		Assertions.assertEquals(1.0, registry.get(BetterleaksScanner.FAILURES_METRIC)
				.tag("reason", "exit_code").counter().count());
		Assertions.assertEquals(1L, registry.get(BetterleaksScanner.DURATION_METRIC)
				.tag("outcome", "failure").timer().count());
	}

	@Test
	public void testCustomRulesRunWithTheirDefinitions() throws Exception {
		com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto custom =
				com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDtoTest
						.validRule();
		custom.setPriority(RulePriority.MEDIUM_HIGH);
		givenEngineFinds(new BetterleaksFinding(custom.getBetterleaksId(), "src/App.java", 7));

		CodeScanReport report =
				scanner.scan(configWith(custom, rule("github-pat", RulePriority.HIGH)));

		@SuppressWarnings("unchecked")
		ArgumentCaptor<Collection<com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto>> definitions =
				ArgumentCaptor.forClass(Collection.class);
		BDDMockito.verify(engine).scan(BDDMockito.eq(workingDirectory),
				BDDMockito.eq(Set.of("github-pat", custom.getBetterleaksId())), BDDMockito.any(),
				definitions.capture());
		MatcherAssert.assertThat(definitions.getValue(), Matchers.contains(custom));
		Assertions.assertEquals(custom.getName(), report.getViolations().get(0).getViolationName());
		Assertions.assertEquals(RulePriority.MEDIUM_HIGH,
				report.getViolations().get(0).getSeverity());
	}

	@Test
	public void testDeclaresItselfSensitiveAndScansTestFolders() {
		Assertions.assertTrue(scanner.isSensitive());
		Assertions.assertEquals(Set.of("node_modules"), scanner.getExcludedFolders());
		Assertions.assertEquals(ScanScope.CHANGED_FILES, scanner.getRequiredScope());
		Assertions.assertEquals(List.of(BetterleaksProvidedRuleDto.class,
				com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto.class),
				scanner.getSupportedRuleClass());
	}
}
