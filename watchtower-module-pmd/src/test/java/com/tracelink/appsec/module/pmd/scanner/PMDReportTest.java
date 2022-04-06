package com.tracelink.appsec.module.pmd.scanner;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;

import net.sourceforge.pmd.Report;
import net.sourceforge.pmd.Report.ConfigurationError;
import net.sourceforge.pmd.Report.ProcessingError;
import net.sourceforge.pmd.Rule;
import net.sourceforge.pmd.RulePriority;
import net.sourceforge.pmd.RuleViolation;
import net.sourceforge.pmd.benchmark.TimingReport;

@ExtendWith(MockitoExtension.class)
public class PMDReportTest {

	@RegisterExtension
	public LogWatchExtension loggerRule = LogWatchExtension.forClass(PMDReport.class);

	@Mock
	Report pmdReport;

	@Mock
	Iterator<RuleViolation> mockVioIter;

	@Test
	public void testReportBlank() {
		BDDMockito.given(pmdReport.iterator()).willReturn(mockVioIter);

		PMDReport sentinelReport = new PMDReport(pmdReport, null);

		Assertions.assertTrue(sentinelReport.getErrors().isEmpty());
		Assertions.assertTrue(sentinelReport.getViolations().isEmpty());
	}

	@Test
	public void testReportHasErrors() {
		String message = "TestMessage";
		ProcessingError pe = new ProcessingError(new Exception(message), "");
		Iterator<ProcessingError> errIter = Arrays.asList(pe).iterator();

		String issue = "TestIssue";
		ConfigurationError ce = new ConfigurationError(null, issue);
		Iterator<ConfigurationError> confErrIter = Arrays.asList(ce).iterator();

		BDDMockito.given(pmdReport.hasErrors()).willReturn(true);
		BDDMockito.given(pmdReport.errors()).willReturn(errIter);

		BDDMockito.given(pmdReport.hasConfigErrors()).willReturn(true);
		BDDMockito.given(pmdReport.configErrors()).willReturn(confErrIter);

		BDDMockito.given(pmdReport.iterator()).willReturn(mockVioIter);

		PMDReport report = new PMDReport(pmdReport, null);

		Assertions.assertEquals(2, report.getErrors().size());
		// first is processing error
		Assertions.assertTrue(report.getErrors().get(0).getErrorMessage().contains(message));
		// next is config error
		Assertions.assertTrue(report.getErrors().get(1).getErrorMessage().contains(issue));
	}

	@Test
	public void testReportViolations() {
		Rule mockRule1 = BDDMockito.mock(Rule.class);
		Rule mockRule2 = BDDMockito.mock(Rule.class);
		RuleViolation mockVio1 = BDDMockito.mock(RuleViolation.class);
		RuleViolation mockVio2 = BDDMockito.mock(RuleViolation.class);
		Iterator<RuleViolation> vioIter = Arrays.asList(mockVio1, mockVio2).iterator();
		String filename = "TestFileName";
		int beginLine = 2;
		String description = "TestDescription";
		String ruleName = "TestRuleName";

		BDDMockito.given(pmdReport.iterator()).willReturn(vioIter);
		BDDMockito.given(mockVio1.getRule()).willReturn(mockRule1);
		BDDMockito.given(mockVio1.getFilename()).willReturn(filename);
		BDDMockito.given(mockVio1.getBeginLine()).willReturn(beginLine);
		BDDMockito.given(mockVio1.getDescription()).willReturn(description);

		BDDMockito.given(mockVio2.getRule()).willReturn(mockRule2);
		BDDMockito.given(mockVio2.getFilename()).willReturn(filename);
		BDDMockito.given(mockVio2.getBeginLine()).willReturn(beginLine);
		BDDMockito.given(mockVio2.getDescription()).willReturn(description);

		BDDMockito.given(mockRule1.getName()).willReturn(ruleName);
		BDDMockito.given(mockRule1.getPriority()).willReturn(RulePriority.HIGH);

		BDDMockito.given(mockRule2.getName()).willReturn(ruleName);
		BDDMockito.given(mockRule2.getPriority()).willReturn(RulePriority.LOW);

		PMDReport report = new PMDReport(pmdReport, null);

		Assertions.assertEquals(2, report.getViolations().size());
		CodeScanViolation sv = report.getViolations().get(0);

		Assertions.assertEquals(ruleName, sv.getViolationName());
		Assertions.assertEquals(filename, sv.getFileName());
		Assertions.assertEquals(beginLine, sv.getLineNum());
		Assertions.assertEquals(RulePriority.HIGH.getName(), sv.getSeverity());
		Assertions.assertEquals(description, sv.getMessage());
	}

	@Test
	public void testReportTimerFinalizing() {
		TimingReport timing = BDDMockito.mock(TimingReport.class);

		BDDMockito.given(pmdReport.iterator()).willReturn(mockVioIter);

		PMDReport sentinelReport = new PMDReport(pmdReport, timing);
		sentinelReport.logRuleBenchmarking();

		List<String> messages = loggerRule.getMessages();
		Assertions.assertEquals(1, messages.size());
		Assertions.assertTrue(messages.get(0).contains("Wall Clock Time"));
	}

}
