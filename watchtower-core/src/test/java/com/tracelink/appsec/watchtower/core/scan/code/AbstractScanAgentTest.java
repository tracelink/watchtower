package com.tracelink.appsec.watchtower.core.scan.code;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleState;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

@ExtendWith({SpringExtension.class, MockitoExtension.class})
@MockitoSettings(strictness = Strictness.LENIENT)
public class AbstractScanAgentTest {
	@Mock
	private ICodeScanner mockScanner;

	@Mock
	private RulesetDto mockRuleset;

	@RegisterExtension
	public CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(AbstractCodeScanAgent.class);

	class MockScanAgent extends AbstractCodeScanAgent<MockScanAgent> {
		Path wd;
		List<CodeScanReport> reports;

		public MockScanAgent(String scanName) {
			super(scanName);
			try {
				wd = Files.createTempDirectory("");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		@Override
		protected void report(List<CodeScanReport> reports) {
			this.reports = reports;
		}

		@Override
		public Path getWorkingDirectory() {
			return wd;
		}

		@Override
		protected void clean() {
			FileUtils.deleteQuietly(wd.toFile());
		}

	}

	@Test
	public void testExecutionSummaryAndPolicyComeFromTheSnapshotEvenWhenSettingsChange() {
		MockCustomRuleDto rule = new MockCustomRuleDto();
		rule.setName("original");
		rule.setId(42L);
		rule.setPriority(RulePriority.HIGH);
		RulesetDto rules = new RulesetDto();
		rules.setRules(java.util.Set.of(rule));
		rules.setBlockingLevel(RulePriority.HIGH);
		CodeScanViolation violation = new CodeScanViolation();
		violation.setSeverity(RulePriority.HIGH);
		CodeScanReport report = new CodeScanReport();
		report.addViolation(violation);
		BDDMockito.when(mockScanner.getSupportedRuleClass()).thenReturn(List.of(MockCustomRuleDto.class));
		BDDMockito.when(mockScanner.scan(BDDMockito.any())).thenAnswer(invocation -> {
			rule.getStewardship().setState(RuleState.RETIRED);
			rules.setBlockingLevel(null);
			return report;
		});
		MockScanAgent agent = new MockScanAgent("snapshot-policy").withRuleset(rules)
				.withScanners(List.of(mockScanner));
		agent.run();
		Assertions.assertFalse(agent.hasFailed());
		Assertions.assertEquals(0, rules.getNumRules());
		Assertions.assertEquals(1, agent.getExecutionSummary().rulesEvaluated());
		Assertions.assertEquals(RuleState.ACTIVE, agent.getExecutionSummary().codeSnapshot().rules().getFirst().state());
		Assertions.assertEquals(Boolean.TRUE, violation.getEffectiveBlocking());
		Assertions.assertEquals("UNKNOWN", agent.getExecutionSummary().codeSnapshot().rules().getFirst().coverage());
		Assertions.assertNull(agent.getExecutionSummary().codeSnapshot().rules().getFirst().evaluatedOpportunities());
	}

	@Test
	public void testAScannerThatReportedErrorsIsFailedWithAReasonThatQuotesNoCode() {
		MockCustomRuleDto rule = new MockCustomRuleDto();
		rule.setName("r");
		rule.setId(61L);
		rule.setPriority(RulePriority.HIGH);
		RulesetDto rules = new RulesetDto();
		rules.setRules(java.util.Set.of(rule));
		CodeScanReport report = new CodeScanReport();
		report.addError(new com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError(
				"Parsing error: Unexpected keyword 'var' in password = \"hunter2\""));
		BDDMockito.when(mockScanner.getSupportedRuleClass()).thenReturn(List.of(MockCustomRuleDto.class));
		BDDMockito.when(mockScanner.scan(BDDMockito.any())).thenReturn(report);
		MockScanAgent agent = new MockScanAgent("failed-reason").withRuleset(rules).withScanners(List.of(mockScanner));

		agent.run();

		var execution = agent.getExecutionSummary().scanners().getFirst();
		Assertions.assertEquals("FAILED", execution.status());
		Assertions.assertEquals("1 problem: Parsing error: Unexpected keyword", execution.reason());
	}

	@Test
	public void testARuleThatCouldNotRunFailsOnlyThatRuleWhileTheScannerStillRan() {
		MockCustomRuleDto kept = new MockCustomRuleDto();
		kept.setName("kept");
		kept.setId(51L);
		kept.setPriority(RulePriority.HIGH);
		MockCustomRuleDto broken = new MockCustomRuleDto();
		broken.setName("broken");
		broken.setId(52L);
		broken.setPriority(RulePriority.HIGH);
		RulesetDto rules = new RulesetDto();
		rules.setRules(java.util.Set.of(kept, broken));
		rules.setBlockingLevel(RulePriority.HIGH);
		CodeScanReport report = new CodeScanReport();
		report.addFailedRule("broken", "No packages or classes specified");
		report.setExecutionStatus("RAN");
		BDDMockito.when(mockScanner.getSupportedRuleClass()).thenReturn(List.of(MockCustomRuleDto.class));
		BDDMockito.when(mockScanner.scan(BDDMockito.any())).thenReturn(report);
		MockScanAgent agent = new MockScanAgent("one-broken-rule").withRuleset(rules).withScanners(List.of(mockScanner));

		agent.run();

		var snapshot = agent.getExecutionSummary().codeSnapshot();
		Assertions.assertFalse(agent.hasFailed());
		Assertions.assertEquals("RAN", snapshot.engines().getFirst().status(), "the scanner ran");
		Assertions.assertEquals("FAILED", snapshot.rules().stream().filter(r -> "broken".equals(r.name())).findFirst().orElseThrow().coverage());
		Assertions.assertEquals("UNKNOWN", snapshot.rules().stream().filter(r -> "kept".equals(r.name())).findFirst().orElseThrow().coverage(),
				"the other rule is not marked failed");
	}

	@Test
	public void testUpstreamHeldRuleReportsButNeverBlocks() {
		MockCustomRuleDto held = new MockCustomRuleDto();
		held.setName("new upstream rule");
		held.setId(43L);
		held.setPriority(RulePriority.HIGH);
		held.getStewardship().setUpstreamHoldSince(1L);
		RulesetDto rules = new RulesetDto();
		rules.setRules(java.util.Set.of(held));
		rules.setBlockingLevel(RulePriority.HIGH);
		CodeScanViolation fromHeld = new CodeScanViolation();
		fromHeld.setSeverity(RulePriority.HIGH);
		fromHeld.setRuleIdentity(new com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity(43L, "Mock", null, null, null));
		CodeScanViolation unmanaged = new CodeScanViolation();
		unmanaged.setSeverity(RulePriority.HIGH);
		CodeScanViolation byName = new CodeScanViolation();
		byName.setSeverity(RulePriority.HIGH);
		byName.setViolationName("new upstream rule");
		byName.setRuleIdentity(com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity.unmanaged("pmd", "new upstream rule"));
		CodeScanReport report = new CodeScanReport();
		report.addViolation(fromHeld);
		report.addViolation(unmanaged);
		report.addViolation(byName);
		BDDMockito.when(mockScanner.getSupportedRuleClass()).thenReturn(List.of(MockCustomRuleDto.class));
		BDDMockito.when(mockScanner.scan(BDDMockito.any())).thenReturn(report);
		new MockScanAgent("upstream-hold").withRuleset(rules).withScanners(List.of(mockScanner)).run();
		Assertions.assertEquals(Boolean.FALSE, fromHeld.getEffectiveBlocking(), "a held upstream rule never blocks");
		Assertions.assertEquals(Boolean.TRUE, unmanaged.getEffectiveBlocking(), "findings without a managed rule keep severity policy");
		Assertions.assertEquals(Boolean.FALSE, byName.getEffectiveBlocking(), "engines reporting an unmanaged identity are matched by the held rule's name");
		Assertions.assertFalse(com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory.definition(held).matches("(?s).*upstream(HoldSince|Held).*"),
				"the installation-local hold never enters a rule definition or export");
	}

	@Test
	public void testWorkingDirectoryNameKeepsOnlySafeCharacters() {
		Assertions.assertEquals(".._evil_repo-1",
				AbstractCodeScanAgent.workingDirectoryPrefix("../evil/repo-1"));
		Assertions.assertEquals("a_b_c", AbstractCodeScanAgent.workingDirectoryPrefix("a\\b c"));
		Assertions.assertEquals("scan", AbstractCodeScanAgent.workingDirectoryPrefix(" "));
		Assertions.assertEquals(64,
				AbstractCodeScanAgent.workingDirectoryPrefix("r".repeat(300)).length());
	}

	@Test
	public void testWorkingDirectoryStaysInTheTempDirectory() throws IOException {
		AbstractCodeScanAgent<?> agent = new AbstractCodeScanAgent<MockScanAgent>("../../etc/x") {
			@Override
			protected void report(List<CodeScanReport> reports) {
			}

			@Override
			protected void clean() {
			}
		};
		Path tmp = Path.of(System.getProperty("java.io.tmpdir")).toRealPath();
		try {
			Assertions.assertEquals(tmp, agent.getWorkingDirectory().toRealPath().getParent());
		} finally {
			FileUtils.deleteQuietly(agent.getWorkingDirectory().toFile());
		}
	}

	@Test
	public void testNullScanners() {
		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(null)
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1);

		try {
			scanAgent.initialize();
			Assertions.fail("Should have thrown an exception.");
		} catch (ScanInitializationException e) {
			Assertions.assertTrue(e.getMessage()
					.contains("Scanner(s) must be configured."));
		}
	}

	@Test
	public void testNullRuleset() {
		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(mockScanner))
				.withRuleset(null)
				.withBenchmarkEnabled(false).withThreads(1);

		try {
			scanAgent.initialize();
			Assertions.fail("Should have thrown an exception.");
		} catch (ScanInitializationException e) {
			Assertions.assertTrue(e.getMessage()
					.contains("Ruleset must be configured"));
		}
	}

	@Test
	public void testThreadsNegative() {
		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(mockScanner))
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(-1);

		try {
			scanAgent.initialize();
			Assertions.fail("Should have thrown an exception.");
		} catch (ScanInitializationException e) {
			Assertions.assertTrue(e.getMessage()
					.contains("Threads must be 0 or greater"));
		}
	}

	@Test
	public void testGetNoRulesForScanner() throws Exception {
		ICodeScanner scanner = BDDMockito.mock(ICodeScanner.class);
		BDDMockito.doReturn(Collections.singletonList(MockCustomRuleDto.class)).when(scanner)
				.getSupportedRuleClass();
		RuleDto rule = BDDMockito.mock(RuleDto.class);
		BDDMockito.when(mockRuleset.getAllRules()).thenReturn(Collections.singleton(rule));

		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(scanner))
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1);
		scanAgent.run();

		List<CodeScanReport> reports = scanAgent.reports;
		MatcherAssert.assertThat(reports, Matchers.hasSize(0));
	}

	@Test
	public void testGetWithRulesForScanner() throws Exception {
		ICodeScanner scanner = BDDMockito.mock(ICodeScanner.class);
		BDDMockito.doReturn(Collections.singletonList(RuleDto.class)).when(scanner)
				.getSupportedRuleClass();
		CodeScanReport report = BDDMockito.mock(CodeScanReport.class);
		BDDMockito.when(scanner.scan(BDDMockito.any())).thenReturn(report);
		RuleDto rule = BDDMockito.mock(RuleDto.class);
		BDDMockito.when(mockRuleset.getAllRules()).thenReturn(Collections.singleton(rule));

		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(scanner))
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(true).withThreads(1);
		scanAgent.run();
		List<CodeScanReport> reports = scanAgent.reports;
		MatcherAssert.assertThat(reports, Matchers.hasSize(1));
		MatcherAssert.assertThat(reports, Matchers.contains(report));
		BDDMockito.verify(report).logRuleBenchmarking();
	}

	@Test
	public void testHasFailedFalseAfterCleanRun() throws Exception {
		ICodeScanner scanner = BDDMockito.mock(ICodeScanner.class);
		BDDMockito.doReturn(Collections.singletonList(RuleDto.class)).when(scanner)
				.getSupportedRuleClass();
		BDDMockito.when(scanner.scan(BDDMockito.any()))
				.thenReturn(BDDMockito.mock(CodeScanReport.class));
		RuleDto rule = BDDMockito.mock(RuleDto.class);
		BDDMockito.when(mockRuleset.getAllRules()).thenReturn(Collections.singleton(rule));

		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(scanner))
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1);
		scanAgent.run();

		Assertions.assertFalse(scanAgent.hasFailed());
	}

	@Test
	public void testHasFailedTrueAfterExceptionDuringScan() throws Exception {
		// IMPROVEMENT_PLAN.md item 4.7: a caller (SqsScanConsumer) needs to know,
		// after an agent's async run() completes, whether it actually succeeded - the
		// CompletableFuture wrapping run() always completes normally, since run()
		// catches every exception internally rather than letting it propagate to the
		// future.
		ICodeScanner scanner = BDDMockito.mock(ICodeScanner.class);
		BDDMockito.doReturn(Collections.singletonList(RuleDto.class)).when(scanner)
				.getSupportedRuleClass();
		BDDMockito.when(scanner.scan(BDDMockito.any())).thenThrow(new RuntimeException("boom"));
		RuleDto rule = BDDMockito.mock(RuleDto.class);
		BDDMockito.when(mockRuleset.getAllRules()).thenReturn(Collections.singleton(rule));

		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(scanner))
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1);
		scanAgent.run();

		Assertions.assertTrue(scanAgent.hasFailed());
	}

	@Test
	public void testScanDurationTimerRecordsSuccessResult() throws Exception {
		// IMPROVEMENT_PLAN.md item 6.6: watchtower.scan.duration, tagged by this
		// agent's getMetricType() (MockScanAgent's default is "unknown") and by
		// hasFailed()'s final value.
		io.micrometer.core.instrument.simple.SimpleMeterRegistry registry =
				new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
		ICodeScanner scanner = BDDMockito.mock(ICodeScanner.class);
		BDDMockito.doReturn(Collections.singletonList(RuleDto.class)).when(scanner)
				.getSupportedRuleClass();
		BDDMockito.when(scanner.scan(BDDMockito.any()))
				.thenReturn(BDDMockito.mock(CodeScanReport.class));
		RuleDto rule = BDDMockito.mock(RuleDto.class);
		BDDMockito.when(mockRuleset.getAllRules()).thenReturn(Collections.singleton(rule));

		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(scanner))
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withMeterRegistry(registry);
		scanAgent.run();

		Assertions.assertEquals(1, registry.get("watchtower.scan.duration")
				.tag("type", "unknown").tag("result", "success").timer().count());
	}

	@Test
	public void testScanDurationTimerRecordsFailureResult() throws Exception {
		io.micrometer.core.instrument.simple.SimpleMeterRegistry registry =
				new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
		ICodeScanner scanner = BDDMockito.mock(ICodeScanner.class);
		BDDMockito.doReturn(Collections.singletonList(RuleDto.class)).when(scanner)
				.getSupportedRuleClass();
		BDDMockito.when(scanner.scan(BDDMockito.any())).thenThrow(new RuntimeException("boom"));
		RuleDto rule = BDDMockito.mock(RuleDto.class);
		BDDMockito.when(mockRuleset.getAllRules()).thenReturn(Collections.singleton(rule));

		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(scanner))
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withMeterRegistry(registry);
		scanAgent.run();

		Assertions.assertEquals(1, registry.get("watchtower.scan.duration")
				.tag("type", "unknown").tag("result", "failure").timer().count());
	}

	@Test
	public void testScanDurationTimerSkippedWhenNoMeterRegistrySet() throws Exception {
		// Existing callers/tests that never call withMeterRegistry() must be
		// unaffected - this is the same test-double every other AbstractScanAgentTest
		// case already uses, without a registry.
		ICodeScanner scanner = BDDMockito.mock(ICodeScanner.class);
		BDDMockito.doReturn(Collections.singletonList(RuleDto.class)).when(scanner)
				.getSupportedRuleClass();
		BDDMockito.when(scanner.scan(BDDMockito.any()))
				.thenReturn(BDDMockito.mock(CodeScanReport.class));
		RuleDto rule = BDDMockito.mock(RuleDto.class);
		BDDMockito.when(mockRuleset.getAllRules()).thenReturn(Collections.singleton(rule));

		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(scanner))
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1);

		Assertions.assertDoesNotThrow(scanAgent::run);
	}

}
