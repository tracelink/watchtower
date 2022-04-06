package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;
import com.tracelink.appsec.watchtower.core.scan.code.scm.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanAgent;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

@ExtendWith(MockitoExtension.class)
public class PRScanAgentTest {

	@Mock
	private IScmApi mockApi;

	@Mock
	private PullRequest mockPR;

	@Mock
	private ICodeScanner mockScanner;

	@Mock
	private RulesetDto mockRuleset;

	@Mock
	private PRScanResultService resultsService;


	@Test
	public void testSourceClientNull() {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(null).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1);

		try {
			scanAgent.initialize();
			Assertions.fail("Should have thrown an exception");
		} catch (ScanInitializationException e) {
			Assertions.assertTrue(e.getMessage()
					.contains("API must be configured"));
		}
	}

	@Test
	public void testScanResultServiceNull() {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1);
		try {
			scanAgent.initialize();
			Assertions.fail("Should have thrown an exception");
		} catch (ScanInitializationException e) {
			Assertions.assertTrue(e.getMessage()
					.contains("Results Service must be configured"));
		}
	}

	@Test
	public void testBadConnection() {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		BDDMockito.when(mockApi.testConnectionForPullRequest(mockPR)).thenReturn(false);

		try {
			scanAgent.initialize();
			Assertions.fail("Should have thrown an exception");
		} catch (ScanInitializationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("Connection to SCM failed for scan"));
		}
	}

	@Test
	public void testCollectFilesException() throws IOException {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		BDDMockito.when(mockApi.testConnectionForPullRequest(mockPR)).thenReturn(true);

		BDDMockito.doThrow(IOException.class).when(mockApi)
				.downloadSourceForPullRequest(BDDMockito.any(), BDDMockito.any());

		try {
			scanAgent.initialize();
			Assertions.fail("Should have thrown an exception");
		} catch (ScanInitializationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("Could not download source"));
		}
	}

	@Test
	public void testInitializeSuccess() throws ScanInitializationException {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);
		BDDMockito.when(mockApi.testConnectionForPullRequest(mockPR)).thenReturn(true);

		scanAgent.initialize();
	}



	@Test
	public void testCollectUninteresting() throws ScanInitializationException, IOException {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);
		BDDMockito.when(mockApi.testConnectionForPullRequest(mockPR)).thenReturn(true);

		Path wd = scanAgent.getWorkingDirectory();
		Path uninDir = wd.resolve("test");
		Path uninFile = wd.resolve("foo.jar");
		Files.createDirectory(uninDir);
		Files.createFile(uninFile);

		scanAgent.initialize();
		Assertions.assertFalse(uninDir.toFile().exists());
		Assertions.assertFalse(uninFile.toFile().exists());
	}

	@Test
	public void testReport() {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		String fileName = "test.java";
		Path filePath = scanAgent.getWorkingDirectory().resolve(fileName);
		int lineNum = 2;
		String message = "message";
		RulePriority severity = RulePriority.HIGH;
		String violationName = "VIOLATION";

		CodeScanViolation violation = new CodeScanViolation();
		violation.setFileName(filePath.toString());
		violation.setLineNum(lineNum);
		violation.setMessage(message);
		violation.setSeverity(severity.getName());
		violation.setSeverityValue(severity.getPriority());
		violation.setViolationName(violationName);

		String errorMessage = "errorMessage";
		CodeScanError error = new CodeScanError(errorMessage);

		CodeScanReport report = BDDMockito.mock(CodeScanReport.class);
		BDDMockito.when(report.getViolations()).thenReturn(Arrays.asList(violation));
		BDDMockito.when(report.getErrors()).thenReturn(Arrays.asList(error));

		BDDMockito.when(mockRuleset.getBlockingLevel()).thenReturn(severity);

		DiffFile diff = BDDMockito.mock(DiffFile.class);
		BDDMockito.when(mockApi.getGitDiffFile(BDDMockito.any(), BDDMockito.any()))
				.thenReturn(diff);
		BDDMockito.when(diff.hasDiffs()).thenReturn(true);

		List<CodeScanReport> reports = Arrays.asList(report);

		scanAgent.report(reports);

		ArgumentCaptor<String> violationsCaptor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockApi).sendComment(BDDMockito.any(), violationsCaptor.capture());

		String violationString = violationsCaptor.getValue();
		MatcherAssert.assertThat(violationString, Matchers.containsString(fileName));
		MatcherAssert.assertThat(violationString, Matchers.containsString("Pre-existing"));
		MatcherAssert.assertThat(violationString,
				Matchers.not(Matchers.containsString("Issues added")));
	}

	@Test
	public void testReportBlockingAndErrors() {
		PRScanAgent scanAgent = new PRScanAgent(mockPR)
				.withScanners(Collections.singleton(mockScanner))
				.withApi(mockApi).withRuleset(mockRuleset)
				.withBenchmarkEnabled(false).withThreads(1)
				.withScanResultService(resultsService);

		String fileName = "test.java";
		Path filePath = scanAgent.getWorkingDirectory().resolve(fileName);
		int lineNum = 2;
		String message = "message";
		RulePriority severity = RulePriority.HIGH;
		String violationName = "VIOLATION";

		CodeScanViolation violation = new CodeScanViolation();
		violation.setFileName(filePath.toString());
		violation.setLineNum(lineNum);
		violation.setMessage(message);
		violation.setSeverity(severity.getName());
		violation.setSeverityValue(severity.getPriority());
		violation.setViolationName(violationName);

		CodeScanReport report = BDDMockito.mock(CodeScanReport.class);
		BDDMockito.when(report.getViolations()).thenReturn(Arrays.asList(violation));
		BDDMockito.when(report.getErrors()).thenReturn(Collections.emptyList());

		BDDMockito.when(mockRuleset.getBlockingLevel()).thenReturn(severity);

		DiffFile diff = BDDMockito.mock(DiffFile.class);
		BDDMockito.when(mockApi.getGitDiffFile(BDDMockito.any(), BDDMockito.any()))
				.thenReturn(diff);
		BDDMockito.when(diff.hasDiffs()).thenReturn(true);
		BDDMockito.when(diff.isLineChanged(lineNum)).thenReturn(true);

		List<CodeScanReport> reports = Arrays.asList(report);

		scanAgent.report(reports);

		ArgumentCaptor<String> violationsCaptor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockApi).sendComment(BDDMockito.any(), violationsCaptor.capture());

		String violationString = violationsCaptor.getValue();
		MatcherAssert.assertThat(violationString, Matchers.containsString(fileName));
		MatcherAssert.assertThat(violationString, Matchers.containsString("Issues added"));
		MatcherAssert.assertThat(violationString,
				Matchers.not(Matchers.containsString("Pre-existing")));

	}
}
