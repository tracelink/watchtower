package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;

class ScannerBadgeTest {

	@Test
	void moduleAndExecutionNamesResolveToOneIdentity() {
		assertEquals("AWS Security Agent", ScannerIdentity.of("AwsSecurityAgent").name());
		assertEquals("AWS Security Agent", ScannerIdentity.of("com.x.AwsSecurityScanner").name());
		assertEquals("ESLint", ScannerIdentity.of("EsLintScanner").name());
		assertEquals("JSON", ScannerIdentity.of("Json").name());
		assertEquals("radar", ScannerIdentity.of("SomethingNew").icon());
		assertEquals("Unknown scanner", ScannerIdentity.of(null).name());
	}

	@Test
	void aScannerWithNoMatchingFilesIsADashedNotNeededTileNotAFailure() {
		String json = ScanExecutionSummaryCodec.encode(List.of(
				new ScannerExecution("PMDScanner", "RAN", 9_400, null),
				new ScannerExecution("CheckovScanner", "NOT_APPLICABLE", 0,
						"No .tf, .json files in this scan")));

		ScannerBadge.Summary tiles = ScannerBadge.from(json, null);

		assertEquals(List.of("ran", "na"), tiles.shown().stream().map(ScannerBadge::state).toList());
		assertEquals("Checkov · not needed · No .tf, .json files in this scan", tiles.shown().get(1).label());
		assertTrue(tiles.unused().isEmpty());
	}

	@Test
	void scannersThatTookPartAreTilesAndTheRestAreSummarized() {
		String json = ScanExecutionSummaryCodec.encode(List.of(
				new ScannerExecution("PMDScanner", "RAN", 9_400, null),
				new ScannerExecution("Json", "SKIPPED", 0, "No compatible rules in the selected ruleset"),
				new ScannerExecution("Opengrep", "DISABLED", 0, "Module disabled or policy changed"),
				new ScannerExecution("CheckovScanner", "FAILED", 0, null)));

		ScannerBadge.Summary tiles = ScannerBadge.from(json, null);

		assertEquals(List.of("ran", "notrun"), tiles.shown().stream().map(ScannerBadge::state).toList());
		assertEquals("PMD · ran · 9.4 s", tiles.shown().get(0).label());
		assertEquals("Checkov · failed", tiles.shown().get(1).label());
		assertEquals("Not used in this scan: JSON (no rules), Opengrep (off)", tiles.getUnusedLabel());
	}

	@Test
	void pullRequestScannersThatRanComeFromTheirTimings() {
		String timings = "[{\"scannerName\":\"Betterleaks\",\"durationMs\":1100},{\"scannerName\":\"PMD\",\"durationMs\":9400}]";
		String executions = ScanExecutionSummaryCodec.encode(List.of(
				new ScannerExecution("Json", "SKIPPED", 0, "No compatible rules in the selected ruleset")));

		ScannerBadge.Summary tiles = ScannerBadge.from(
				com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanTimings.executions(timings, executions), null);

		assertEquals(List.of("Betterleaks", "PMD"), tiles.shown().stream().map(ScannerBadge::name).toList());
		assertEquals(1, tiles.unused().size());
	}

	@Test
	void listRowsFoldExtraTilesSoTheCellNeverWraps() {
		String json = ScanExecutionSummaryCodec.encode(List.of(
				new ScannerExecution("PMDScanner", "RAN", 2_100, null),
				new ScannerExecution("EsLintScanner", "RAN", 1_000, null),
				new ScannerExecution("Betterleaks", "RAN", 500, null),
				new ScannerExecution("CheckovScanner", "FAILED", 0, null),
				new ScannerExecution("Json", "SKIPPED", 0, null)));

		ScannerBadge.Summary tiles = ScannerBadge.from(json, null);

		assertEquals(List.of("Checkov", "PMD"), tiles.getVisible().stream().map(ScannerBadge::name).toList(),
				"the scanner that did not finish is drawn first");
		assertEquals(3, tiles.getMoreCount(), "two hidden tiles plus one unused scanner");
		assertEquals("Also: ESLint · ran · 1.0 s, Betterleaks · ran · 500 ms · Not used in this scan: JSON (no rules)",
				tiles.getMoreLabel());
	}

	@Test
	void fewTilesAreAllDrawnAndUnusedScannersAreTheMoreChip() {
		String json = ScanExecutionSummaryCodec.encode(List.of(
				new ScannerExecution("PMDScanner", "RAN", 2_100, null),
				new ScannerExecution("Json", "SKIPPED", 0, null)));

		ScannerBadge.Summary tiles = ScannerBadge.from(json, null);

		assertEquals(1, tiles.getVisible().size());
		assertEquals(1, tiles.getMoreCount());
		assertEquals("Not used in this scan: JSON (no rules)", tiles.getMoreLabel());
	}

	@Test
	void olderScansWithoutRecordsHaveNoTiles() {
		assertTrue(!ScannerBadge.from((String) null, null).isRecorded());
		assertTrue(!ScannerBadge.from("not json", "not json either").isRecorded());
	}

	@Test
	void finishedStatusesUseShortWordsWithTheMeaningInTheHoverText() {
		var full = StatusPresentationModel.from(new ScanAssessment("COMPLETED", "COMPLETE", List.of()));
		var partial = StatusPresentationModel.from(new ScanAssessment("COMPLETED", "INCOMPLETE",
				List.of("AWS Security Agent is disabled.")));
		var unknown = StatusPresentationModel.from(ScanStatus.DONE);

		assertEquals("Full scan", full.getLabel());
		assertEquals("Partial scan", partial.getLabel());
		assertEquals("warning", partial.getTone());
		assertTrue(partial.getAccessibleText().contains("AWS Security Agent is disabled."));
		assertEquals("Finished", unknown.getLabel());
		assertTrue(full.isProcessingCompleted() && partial.isProcessingCompleted() && unknown.isProcessingCompleted());
		assertTrue(!StatusPresentationModel.from(ScanStatus.FAILED).isProcessingCompleted());
	}

	private static com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference provider(String state, boolean complete) {
		var status = new com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.Status("run", state, null, "c1", "c0",
				"cr-1", "cj-1", 0, 0, true, complete, 30, 1, java.util.Map.of(), java.util.Map.of(), List.of());
		return new com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference("AWS_SECURITY_AGENT", "run", null, status,
				null, null, null, null, java.util.Map.of(), 0);
	}

	@Test
	void aProviderReviewThatIsStillWorkingIsYellowNotRed() {
		for (String state : List.of("QUEUED", "PREPARING", "INPUT_READY", "CREATING", "REVIEW_READY", "STARTING", "RUNNING", "IMPORTING")) {
			ScannerBadge tile = ScannerBadge.fromReferences(List.of(), List.of(provider(state, false))).shown().get(0);
			assertEquals("running", tile.state(), state);
			assertEquals("AWS Security Agent · running", tile.label());
		}
	}

	@Test
	void aProviderReviewThatEndedWithoutFinishingIsStillRed() {
		for (String state : List.of("FAILED", "CANCELED", "UNAVAILABLE", "PARTIAL", "NEEDS_RECONCILIATION")) {
			assertEquals("notrun", ScannerBadge.fromReferences(List.of(), List.of(provider(state, false))).shown().get(0).state(), state);
		}
		assertEquals("ran", ScannerBadge.fromReferences(List.of(), List.of(provider("COMPLETE", true))).shown().get(0).state());
	}

	@Test
	void aRunningTileIsNeverSortedAmongTheFailures() {
		// Failures come first in a crowded row; a running scanner is not one.
		var tiles = ScannerBadge.fromReferences(
				List.of(new ScannerExecution("PMDScanner", "RAN", 1_000, null), new ScannerExecution("RegexScanner", "RAN", 1_000, null),
						new ScannerExecution("JsonScanner", "FAILED", 10, null)),
				List.of(provider("RUNNING", false)));
		assertEquals("notrun", tiles.getVisible().get(0).state());
	}
}
