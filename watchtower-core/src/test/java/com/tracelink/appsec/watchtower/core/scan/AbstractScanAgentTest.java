package com.tracelink.appsec.watchtower.core.scan;

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
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.AbstractCodeScanAgent;

@ExtendWith(SpringExtension.class)
public class AbstractScanAgentTest {
	@Mock
	private IScanner mockScanner;

	@Mock
	private RulesetDto mockRuleset;

	@RegisterExtension
	public CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(AbstractScanAgent.class);

	class MockScanAgent extends AbstractCodeScanAgent<MockScanAgent> {
		Path wd;
		List<ScanReport> reports;

		public MockScanAgent(String scanName) {
			super(scanName);
			try {
				wd = Files.createTempDirectory("");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		@Override
		protected void initialize() throws ScanInitializationException {
			super.initialize();
		}

		@Override
		protected void report(List<ScanReport> reports) {
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
		IScanner scanner = BDDMockito.mock(IScanner.class);
		BDDMockito.doReturn(MockCustomRuleDto.class).when(scanner).getSupportedRuleClass();
		RuleDto rule = BDDMockito.mock(RuleDto.class);
		BDDMockito.when(mockRuleset.getAllRules()).thenReturn(Collections.singleton(rule));

		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(scanner))
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1);
		scanAgent.run();

		List<ScanReport> reports = scanAgent.reports;
		MatcherAssert.assertThat(reports, Matchers.hasSize(0));
	}

	@Test
	public void testGetWithRulesForScanner() throws Exception {
		IScanner scanner = BDDMockito.mock(IScanner.class);
		BDDMockito.doReturn(RuleDto.class).when(scanner).getSupportedRuleClass();
		ScanReport report = BDDMockito.mock(ScanReport.class);
		BDDMockito.when(scanner.scan(BDDMockito.any())).thenReturn(report);
		RuleDto rule = BDDMockito.mock(RuleDto.class);
		BDDMockito.when(mockRuleset.getAllRules()).thenReturn(Collections.singleton(rule));

		MockScanAgent scanAgent = new MockScanAgent("name")
				.withScanners(Collections.singleton(scanner))
				.withRuleset(mockRuleset)
				.withBenchmarkEnabled(true).withThreads(1);
		scanAgent.run();
		List<ScanReport> reports = scanAgent.reports;
		MatcherAssert.assertThat(reports, Matchers.hasSize(1));
		MatcherAssert.assertThat(reports, Matchers.contains(report));
		BDDMockito.verify(report).logRuleBenchmarking();
	}

}
