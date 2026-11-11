package com.tracelink.appsec.module.opengrep.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.process.ProcessResult;

/** One broken file must not hide the findings of the others; anything untrustworthy still refuses the run. */
class OpengrepAnalysisTest {
	private static final Path ROOT = Path.of("/work/repo");

	private static ProcessResult result(int exit, String stdout) {
		return new ProcessResult(exit, stdout, "", false, false, false, Duration.ofSeconds(1));
	}

	private static String report(String results, String errors) {
		return "{\"results\":[" + results + "],\"errors\":[" + errors
				+ "],\"paths\":{\"scanned\":[\"/work/repo/a.py\"]}}";
	}

	@Test
	void aCleanRunHasNothingUnanalyzed() throws Exception {
		var analysis = OpengrepScanner.analyze(result(0, report("", "")), ROOT);

		assertThat(analysis.unanalyzedFiles()).isZero();
	}

	@Test
	void aFileItCouldNotParseIsCountedAndTheOtherFindingsKept() throws Exception {
		String error = "{\"type\":\"Syntax error\",\"level\":\"warn\",\"path\":\"/work/repo/k8s/bad.yaml\"}";
		var analysis = OpengrepScanner.analyze(result(2, report("{\"check_id\":\"x\"}", error)), ROOT);

		assertThat(analysis.unanalyzedFiles()).isEqualTo(1);
		assertThat(analysis.output().path("results")).hasSize(1);
	}

	@Test
	void theSameFileReportedTwiceCountsOnce() throws Exception {
		String error = "{\"type\":\"Syntax error\",\"path\":\"bad.yaml\"}";
		var analysis = OpengrepScanner.analyze(result(2, report("", error + "," + error)), ROOT);

		assertThat(analysis.unanalyzedFiles()).isEqualTo(1);
	}

	@Test
	void aRuleOrConfigurationErrorRefusesTheRun() {
		String error = "{\"type\":\"Rule parse error\",\"level\":\"error\",\"path\":\"/task/rules.json\"}";

		assertThatThrownBy(() -> OpengrepScanner.analyze(result(2, report("", error)), ROOT))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void anErrorWithNoFileRefusesTheRun() {
		assertThatThrownBy(() -> OpengrepScanner.analyze(result(2, report("", "{\"type\":\"Other\"}")), ROOT))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void anErrorAboutAPathOutsideTheScanRefusesTheRun() {
		String error = "{\"type\":\"Syntax error\",\"path\":\"/etc/passwd\"}";

		assertThatThrownBy(() -> OpengrepScanner.analyze(result(2, report("", error)), ROOT))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void aFailingExitWithNoOutputRefusesTheRun() {
		assertThatThrownBy(() -> OpengrepScanner.analyze(result(2, ""), ROOT))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("exit code 2");
	}

	@Test
	void aFailingExitWithAReportThatExplainsNothingRefusesTheRun() {
		assertThatThrownBy(() -> OpengrepScanner.analyze(result(2, report("", "")), ROOT))
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void aTimedOutRunRefusesTheRun() {
		var timedOut = new ProcessResult(-1, report("", ""), "", true, false, false, Duration.ofSeconds(90));

		assertThatThrownBy(() -> OpengrepScanner.analyze(timedOut, ROOT))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("timed out");
	}
}
