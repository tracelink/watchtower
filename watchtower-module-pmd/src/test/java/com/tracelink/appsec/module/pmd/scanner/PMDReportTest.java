package com.tracelink.appsec.module.pmd.scanner;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;

import net.sourceforge.pmd.benchmark.TimingReport;
import net.sourceforge.pmd.lang.document.FileId;
import net.sourceforge.pmd.lang.rule.Rule;
import net.sourceforge.pmd.lang.rule.RulePriority;
import net.sourceforge.pmd.reporting.Report;
import net.sourceforge.pmd.reporting.RuleViolation;

/**
 * {@code Report} is {@code final} with no public constructor in PMD 7 (built only via
 * {@link Report#buildReport}), so unlike PMD 6 these tests build real {@link Report} instances
 * through that factory instead of mocking {@code Report} directly - Mockito 4.5.1 (this
 * project's version) cannot mock final classes without the inline mock maker, which this project
 * doesn't opt into.
 *
 * <p>
 * Note: {@code Report.ConfigurationError} has no public way to be added to a built
 * {@code Report} (the {@code FileAnalysisListener} used by {@code buildReport} only exposes
 * {@code onRuleViolation}/{@code onError(ProcessingError)}), so the configuration-error path this
 * test used to cover for PMD 6 isn't independently testable here; {@link PMDReport}'s production
 * code still reads {@code report.getConfigurationErrors()} correctly when PMD's own engine
 * populates it during a real scan.
 */
@ExtendWith(MockitoExtension.class)
public class PMDReportTest {

	@RegisterExtension
	public LogWatchExtension loggerRule = LogWatchExtension.forClass(PMDReport.class);

	@Test
	public void testReportBlank() {
		Report pmdReport = Report.buildReport(listener -> {
		});

		PMDReport sentinelReport = new PMDReport(pmdReport, null);

		Assertions.assertTrue(sentinelReport.getErrors().isEmpty());
		Assertions.assertTrue(sentinelReport.getViolations().isEmpty());
	}

	@Test
	public void testReportHasErrors() {
		String message = "TestMessage";
		Report.ProcessingError pe =
				new Report.ProcessingError(new Exception(message), FileId.UNKNOWN);

		Report pmdReport = Report.buildReport(listener -> listener.onError(pe));

		PMDReport report = new PMDReport(pmdReport, null);

		Assertions.assertEquals(1, report.getErrors().size());
		Assertions.assertTrue(report.getErrors().get(0).getErrorMessage().contains(message));
	}

	@Test
	public void testReportViolations() {
		Rule mockRule1 = BDDMockito.mock(Rule.class);
		Rule mockRule2 = BDDMockito.mock(Rule.class);
		RuleViolation mockVio1 = BDDMockito.mock(RuleViolation.class);
		RuleViolation mockVio2 = BDDMockito.mock(RuleViolation.class);
		FileId mockFileId = BDDMockito.mock(FileId.class);
		String filename = "TestFileName";
		// Distinct line numbers so each violation can be matched regardless of the order
		// Report's own internal sorting places them in - unlike PMD 6's mocked iterator, a real
		// Report (built via Report.buildReport, since Report is final and unmockable here) does
		// not guarantee to preserve onRuleViolation() call order.
		int highLine = 2;
		int lowLine = 5;
		String description = "TestDescription";
		String ruleName = "TestRuleName";

		BDDMockito.given(mockFileId.getAbsolutePath()).willReturn(filename);

		BDDMockito.given(mockVio1.getRule()).willReturn(mockRule1);
		BDDMockito.given(mockVio1.getFileId()).willReturn(mockFileId);
		BDDMockito.given(mockVio1.getBeginLine()).willReturn(highLine);
		BDDMockito.given(mockVio1.getDescription()).willReturn(description);

		BDDMockito.given(mockVio2.getRule()).willReturn(mockRule2);
		BDDMockito.given(mockVio2.getFileId()).willReturn(mockFileId);
		BDDMockito.given(mockVio2.getBeginLine()).willReturn(lowLine);
		BDDMockito.given(mockVio2.getDescription()).willReturn(description);

		BDDMockito.given(mockRule1.getName()).willReturn(ruleName);
		BDDMockito.given(mockRule1.getPriority()).willReturn(RulePriority.HIGH);

		BDDMockito.given(mockRule2.getName()).willReturn(ruleName);
		BDDMockito.given(mockRule2.getPriority()).willReturn(RulePriority.LOW);

		Report pmdReport = Report.buildReport(listener -> {
			listener.onRuleViolation(mockVio1);
			listener.onRuleViolation(mockVio2);
		});

		PMDReport report = new PMDReport(pmdReport, null);

		Assertions.assertEquals(2, report.getViolations().size());
		CodeScanViolation highSeveritySv = report.getViolations().stream()
				.filter(v -> v.getLineNum() == highLine).findFirst()
				.orElseThrow(() -> new AssertionError("Expected a violation at line " + highLine));

		Assertions.assertEquals(ruleName, highSeveritySv.getViolationName());
		Assertions.assertEquals(filename, highSeveritySv.getFileName());
		Assertions.assertEquals(highLine, highSeveritySv.getLineNum());
		Assertions.assertEquals(com.tracelink.appsec.watchtower.core.rule.RulePriority.HIGH,
				highSeveritySv.getSeverity());
		Assertions.assertEquals(description, highSeveritySv.getMessage());
	}

	private static Report reportWith(List<Report.ConfigurationError> configErrors, List<Report.ProcessingError> processingErrors) {
		// Report is final; Mockito's inline mock maker (the default in the project's Mockito) can stand in for one that
		// holds configuration errors, which a real Report built by Report.buildReport cannot be given.
		Report pmdReport = BDDMockito.mock(Report.class);
		BDDMockito.given(pmdReport.getConfigurationErrors()).willReturn(configErrors);
		BDDMockito.given(pmdReport.getProcessingErrors()).willReturn(processingErrors);
		BDDMockito.given(pmdReport.getViolations()).willReturn(List.of());
		return pmdReport;
	}

	@Test
	public void testAMisconfiguredRuleFailsOnlyThatRuleAndTheScannerStillRan() {
		Rule dropped = BDDMockito.mock(Rule.class);
		BDDMockito.given(dropped.getName()).willReturn("LoosePackageCoupling");

		PMDReport report = new PMDReport(reportWith(
				List.of(new Report.ConfigurationError(dropped, "No packages or classes specified")), List.of()), null);

		Assertions.assertEquals(java.util.Map.of("LoosePackageCoupling", "No packages or classes specified"),
				report.getFailedRules());
		Assertions.assertEquals("RAN", report.getExecutionStatus(), "PMD ran; only the dropped rule did not");
		Assertions.assertEquals(1, report.getErrors().size(), "the message is still kept");
		Assertions.assertTrue(report.getErrors().get(0).getErrorMessage().contains("Poorly Configured Rule"));
	}

	@Test
	public void testAFileThatCouldNotBeProcessedStillFailsTheScannerEvenWithADroppedRule() {
		Rule dropped = BDDMockito.mock(Rule.class);
		BDDMockito.given(dropped.getName()).willReturn("LoosePackageCoupling");
		Report.ProcessingError broken = new Report.ProcessingError(new Exception("boom"), FileId.UNKNOWN);

		PMDReport report = new PMDReport(reportWith(
				List.of(new Report.ConfigurationError(dropped, "No packages or classes specified")), List.of(broken)), null);

		Assertions.assertNull(report.getExecutionStatus(), "the errors then decide, and they fail the scanner");
		Assertions.assertEquals(2, report.getErrors().size());
		Assertions.assertTrue(report.getFailedRules().containsKey("LoosePackageCoupling"));
	}

	@Test
	public void testAConfigurationProblemWithNoRuleToNameStillFailsTheScanner() {
		PMDReport report = new PMDReport(reportWith(List.of(new Report.ConfigurationError(null, "unknown problem")), List.of()), null);

		Assertions.assertNull(report.getExecutionStatus());
		Assertions.assertTrue(report.getFailedRules().isEmpty());
		Assertions.assertEquals(1, report.getErrors().size());
	}

	@Test
	public void testReportTimerFinalizing() {
		TimingReport timing = BDDMockito.mock(TimingReport.class);
		Report pmdReport = Report.buildReport(listener -> {
		});

		PMDReport sentinelReport = new PMDReport(pmdReport, timing);
		sentinelReport.logRuleBenchmarking();

		List<String> messages = loggerRule.getMessages();
		Assertions.assertEquals(1, messages.size());
		Assertions.assertTrue(messages.get(0).contains("Wall Clock Time"));
	}

}
