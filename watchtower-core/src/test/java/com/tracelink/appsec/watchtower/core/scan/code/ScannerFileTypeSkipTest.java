package com.tracelink.appsec.watchtower.core.scan.code;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

/** A scanner with file types does not start when the scan has none of them. */
class ScannerFileTypeSkipTest {
	private Path workingDirectory;
	private RulesetDto ruleset;

	class Agent extends AbstractCodeScanAgent<Agent> {
		Agent() {
			super("file-types");
		}

		@Override
		protected void report(List<CodeScanReport> reports) {
		}

		@Override
		public Path getWorkingDirectory() {
			return workingDirectory;
		}

		@Override
		protected void clean() {
		}
	}

	@BeforeEach
	void setUp() throws IOException {
		workingDirectory = Files.createTempDirectory("file-types-test");
		MockCustomRuleDto rule = new MockCustomRuleDto();
		rule.setName("rule");
		rule.setId(1L);
		rule.setPriority(RulePriority.HIGH);
		ruleset = new RulesetDto();
		ruleset.setRules(Set.of(rule));
		ruleset.setBlockingLevel(RulePriority.HIGH);
	}

	@AfterEach
	void tearDown() {
		FileUtils.deleteQuietly(workingDirectory.toFile());
	}

	private ICodeScanner scanner(String name, List<String> types) {
		ICodeScanner scanner = Mockito.mock(ICodeScanner.class);
		Mockito.when(scanner.getSupportedRuleClass()).thenReturn(List.of(MockCustomRuleDto.class));
		Mockito.when(scanner.getFileTypes()).thenReturn(types);
		Mockito.when(scanner.executionName()).thenReturn(name);
		Mockito.when(scanner.scan(Mockito.any())).thenReturn(new CodeScanReport());
		return scanner;
	}

	private ScanExecutionSummary run(ICodeScanner... scanners) {
		Agent agent = new Agent().withRuleset(ruleset).withScanners(List.of(scanners));
		agent.run();
		return agent.getExecutionSummary();
	}

	private void file(String relative) throws IOException {
		Path path = workingDirectory.resolve(relative);
		Files.createDirectories(path.getParent());
		Files.writeString(path, "x");
	}

	@Test
	void scannerIsNotStartedWhenNoFileHasItsType() throws IOException {
		file("README.md");
		ICodeScanner checkov = scanner("CheckovScanner", List.of(".tf", ".yaml"));

		ScanExecutionSummary summary = run(checkov);

		Mockito.verify(checkov, Mockito.never()).scan(Mockito.any());
		assertThat(summary.scanners()).hasSize(1);
		assertThat(summary.scanners().getFirst().status()).isEqualTo("NOT_APPLICABLE");
		assertThat(summary.scanners().getFirst().reason()).contains(".tf", ".yaml");
		assertThat(summary.codeSnapshot().engines().getFirst().status()).isEqualTo("NOT_APPLICABLE");
		assertThat(summary.codeSnapshot().rules().getFirst().coverage()).isEqualTo("NOT_APPLICABLE");
	}

	@Test
	void scannerRunsWhenAFileHasItsType() throws IOException {
		file("infra/deep/main.tf");
		ICodeScanner checkov = scanner("CheckovScanner", List.of(".tf"));

		ScanExecutionSummary summary = run(checkov);

		Mockito.verify(checkov).scan(Mockito.any());
		assertThat(summary.scanners().getFirst().status()).isEqualTo("RAN");
	}

	@Test
	void emptyTypesMeanEveryFileSoTheScannerAlwaysRuns() throws IOException {
		file("README.md");
		ICodeScanner everything = scanner("RegexScanner", List.of());

		run(everything);

		Mockito.verify(everything).scan(Mockito.any());
	}

	@Test
	void onlyTheScannerWithoutMatchingFilesIsSkipped() throws IOException {
		file("src/App.java");
		ICodeScanner pmd = scanner("PMDScanner", List.of(".java"));
		ICodeScanner checkov = scanner("CheckovScanner", List.of(".tf"));

		ScanExecutionSummary summary = run(pmd, checkov);

		Mockito.verify(pmd).scan(Mockito.any());
		Mockito.verify(checkov, Mockito.never()).scan(Mockito.any());
		assertThat(summary.scanners()).extracting(s -> s.scannerName() + ":" + s.status())
				.containsExactly("PMD:RAN", "Checkov:NOT_APPLICABLE");
	}

	@Test
	void aScannerThatCannotSayWhichFileTypesItHasStillRuns() throws IOException {
		file("README.md");
		ICodeScanner broken = scanner("PMDScanner", List.of(".java"));
		Mockito.when(broken.getFileTypes()).thenThrow(new IllegalStateException("settings unavailable"));

		run(broken);

		Mockito.verify(broken).scan(Mockito.any());
	}

	@Test
	void anUnreadableWorkingDirectoryFailsOpenSoTheScannerRuns() throws IOException {
		FileUtils.deleteQuietly(workingDirectory.toFile());
		ICodeScanner checkov = scanner("CheckovScanner", List.of(".tf"));

		run(checkov);

		Mockito.verify(checkov).scan(Mockito.any());
	}
}
