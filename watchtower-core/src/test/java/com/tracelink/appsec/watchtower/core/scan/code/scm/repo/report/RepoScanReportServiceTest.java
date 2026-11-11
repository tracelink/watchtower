package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.BDDMockito;
import org.mockito.Mockito;

import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeExcerpts;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultCodeLine;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultFile;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

public class RepoScanReportServiceTest {

	private static final String SOURCE = String.join("\n", "package a;", "class App {",
			"  String sql = \"select \" + input;", "  String key = \"AKIA0000SECRET\";", "}");

	private RuleService rules;

	private IScmApi api;

	private RepoScanReportService service;

	private RepoScanEntity scan;

	@BeforeEach
	public void setup() {
		rules = Mockito.mock(RuleService.class);
		api = Mockito.mock(IScmApi.class);
		ApiIntegrationEntity bb = Mockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(bb.createApi()).thenReturn(api);
		ApiIntegrationService integrations = Mockito.mock(ApiIntegrationService.class);
		BDDMockito.when(integrations.findByLabel("bb")).thenReturn(bb);
		service = new RepoScanReportService(Mockito.mock(RepoReportStore.class), integrations,
				rules, Mockito.mock(ScanRegistrationService.class));
		RepositoryEntity repo = new RepositoryEntity();
		repo.setApiLabel("bb");
		repo.setRepoName("payments-api");
		scan = new RepoScanEntity();
		scan.setRepository(repo);
		scan.setCommitHash("abc123");
		BDDMockito.when(api.fetchFileAtCommit("payments-api", "abc123", "src/App.java"))
				.thenReturn(com.tracelink.appsec.watchtower.core.scan.code.scm.api.FileFetch
						.found(SOURCE));
	}

	@ParameterizedTest
	@ValueSource(strings = {"pom.xml", "src/main/App.java", "a/b..c/d.txt", "My File.txt"})
	public void repositoryPathsArePlain(String path) {
		Assertions.assertTrue(RepoScanReportService.isPlainPath(path));
	}

	@ParameterizedTest
	@ValueSource(strings = {"", " ", "/etc/passwd", "../other-repo/x", "a/../../b", "a/..",
			"a?at=main", "a#frag", "a\\b", "a\nb", "a\u0000b"})
	public void pathsThatCouldChangeTheScmRequestAreNot(String path) {
		Assertions.assertFalse(RepoScanReportService.isPlainPath(path));
	}

	@Test
	public void theCodeSectionListsEachFileOnceInPathOrder() {
		RepoScanReport report = report(finding("sqli", "src/App.java", 3, false),
				finding("key", "src/App.java", 4, true), finding("x", "README.md", 1, false),
				finding("y", "../escape", 1, false));

		Assertions.assertEquals(List.of(new RepoScanReportService.CodeFile("README.md", 1),
				new RepoScanReportService.CodeFile("src/App.java", 2)), service.codeFiles(report));
	}

	@Test
	public void aFileShowsItsCodeAtTheScannedCommitWithTheSecretLineMasked() {
		RepoScanReport report = report(finding("sqli", "src/App.java", 3, false),
				finding("key", "src/App.java", 4, true));

		PRScanResultFile file = service.codeFile(scan, report, "src/App.java");

		Assertions.assertTrue(file.isSourceAvailable());
		Assertions.assertEquals(2, file.getFindingCount());
		List<PRScanResultCodeLine> lines = file.getBlocks().get(0).getLines();
		Assertions.assertEquals(1, lines.get(0).getLineNumber(), "context around the finding");
		Assertions.assertTrue(lines.get(2).isViolationLine());
		Assertions.assertTrue(lines.get(2).getText().contains("select"));
		Assertions.assertEquals(CodeExcerpts.MASKED_LINE_TEXT, lines.get(3).getText());
		Assertions.assertTrue(lines.stream().noneMatch(l -> l.getText().contains("AKIA")));
	}

	@Test
	public void anOlderReportAsksTheRuleAndAnUnknownRuleIsTreatedAsASecret() {
		// Reports written before the flag was recorded have no "sensitive"
		RepoScanReport report = report(finding("gone-rule", "src/App.java", 4, null));

		PRScanResultFile file = service.codeFile(scan, report, "src/App.java");

		Assertions.assertEquals(CodeExcerpts.MASKED_LINE_TEXT,
				file.getBlocks().get(0).getLines().get(0).getText());
	}

	@Test
	public void aFileTheScmDoesNotReturnSaysSo() {
		RepoScanReport report = report(finding("sqli", "src/Gone.java", 3, false));
		Assertions.assertFalse(service.codeFile(scan, report, "src/Gone.java")
				.isSourceAvailable());
	}

	private static RepoScanReport.Finding finding(String rule, String file, int line,
			Boolean sensitive) {
		return new RepoScanReport.Finding(rule, "High", file, line, "m", rule + line, false,
				sensitive);
	}

	private static RepoScanReport report(RepoScanReport.Finding... findings) {
		return new RepoScanReport(1, 4, "bb", "payments-api", "main", "abc123", "Default",
				List.of(findings), List.of(), List.of(), findings.length);
	}

	@Test
	void aFileTheServerWillNotGiveSaysWhy() {
		BDDMockito.when(api.fetchFileAtCommit("payments-api", "abc123", "src/Gone.java"))
				.thenReturn(com.tracelink.appsec.watchtower.core.scan.code.scm.api.FileFetch
						.unavailable("The file is not at the scanned commit."));
		RepoScanReport report = new RepoScanReport(RepoScanReport.SCHEMA, 1, "bb", "payments-api",
				"main", "abc123", "rules", java.util.List.of(new RepoScanReport.Finding("rule", "High",
						"src/Gone.java", 2, "m", "fp", false, false)), java.util.List.of(), java.util.List.of(), 1);

		var file = service.codeFile(scan, report, "src/Gone.java");

		org.junit.jupiter.api.Assertions.assertFalse(file.isSourceAvailable());
		org.junit.jupiter.api.Assertions.assertEquals("The file is not at the scanned commit.",
				file.getSourceUnavailableReason());
	}
}
