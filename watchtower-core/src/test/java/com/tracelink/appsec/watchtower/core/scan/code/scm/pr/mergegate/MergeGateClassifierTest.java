package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateClassifier.Bypass;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateClassifier.MergedPullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateClassifier.Scan;

public class MergeGateClassifierTest {
	private static final long MERGED_AT = 10_000L;
	private static final MergedPullRequest MERGED = new MergedPullRequest(MERGED_AT, "abc", false);

	private static MergeGateOutcome classify(MergedPullRequest pr, List<Scan> scans,
			List<Bypass> bypasses, Set<Long> bypassedWhenFound) {
		return MergeGateClassifier.classify(pr, scans, bypasses, bypassedWhenFound);
	}

	private static MergeGateOutcome classify(List<Scan> scans) {
		return classify(MERGED, scans, List.of(), Set.of());
	}

	@Test
	public void aCleanScanOfTheMergedCommitBeforeTheMergeIsGated() {
		Assertions.assertEquals(MergeGateOutcome.SCANNED_CLEAN,
				classify(List.of(new Scan(1, "ABC", ScanStatus.DONE, 9_000L, false))));
	}

	@Test
	public void anAbbreviatedMergedCommitFindsItsFullLengthScanEvenWhenAScanWasPendingAtTheMerge() {
		String full = "4539c9115975a1b2c3d4e5f60718293a4b5c6d7e";
		String twelve = "4539c9115975";
		List<Scan> fullScan = List.of(new Scan(1, full, ScanStatus.DONE, 9_000L, false));
		List<Scan> shortScan = List.of(new Scan(1, twelve, ScanStatus.DONE, 9_000L, false));

		Assertions.assertEquals(MergeGateOutcome.SCANNED_CLEAN, classify(
				new MergedPullRequest(MERGED_AT, twelve, true), fullScan, List.of(), Set.of()),
				"a 12-character merged commit from the webhook matches the 40-character scan");
		Assertions.assertEquals(MergeGateOutcome.SCANNED_CLEAN, classify(
				new MergedPullRequest(MERGED_AT, full, true), shortScan, List.of(), Set.of()),
				"and the other way round");
		Assertions.assertEquals(MergeGateOutcome.SCAN_IN_PROGRESS, classify(
				new MergedPullRequest(MERGED_AT, "4539c9115975", true),
				List.of(new Scan(2, "ffff00001111aaaa", ScanStatus.DONE, 9_000L, false)),
				List.of(), Set.of()), "a different commit still does not gate the merge");
	}

	@Test
	public void aBlockedScanCountsAsBypassedOnlyWhenABypassWasActiveAtTheMerge() {
		List<Scan> blocked = List.of(new Scan(1, "abc", ScanStatus.DONE, 9_000L, true));

		Assertions.assertEquals(MergeGateOutcome.BLOCKED_UNBYPASSED, classify(blocked));
		Assertions.assertEquals(MergeGateOutcome.BLOCKED_BYPASSED, classify(MERGED, blocked,
				List.of(new Bypass(9_500L, null)), Set.of()));
		Assertions.assertEquals(MergeGateOutcome.BLOCKED_UNBYPASSED, classify(MERGED, blocked,
				List.of(new Bypass(9_500L, 9_800L), new Bypass(11_000L, null)), Set.of()),
				"revoked before the merge, or made after it");
	}

	@Test
	public void findingsABypassCoveredWhenFoundCountAsBypassedWhileItLasts() {
		List<Scan> covered = List.of(new Scan(1, "abc", ScanStatus.DONE, 9_000L, false));

		Assertions.assertEquals(MergeGateOutcome.BLOCKED_BYPASSED, classify(MERGED, covered,
				List.of(new Bypass(8_000L, null)), Set.of(1L)));
		Assertions.assertEquals(MergeGateOutcome.BLOCKED_UNBYPASSED, classify(MERGED, covered,
				List.of(new Bypass(8_000L, 9_500L)), Set.of(1L)),
				"revoked before the merge, and merged before the rescan it queued");
	}

	@Test
	public void theNewestCompletedScanOfTheMergedCommitDecides() {
		Assertions.assertEquals(MergeGateOutcome.SCANNED_CLEAN, classify(List.of(
				new Scan(1, "abc", ScanStatus.DONE, 8_000L, true),
				new Scan(2, "abc", ScanStatus.DONE, 9_000L, false))));
	}

	@Test
	public void aScanStillRunningOrFinishingAfterTheMergeWasInProgress() {
		Assertions.assertEquals(MergeGateOutcome.SCAN_IN_PROGRESS,
				classify(List.of(new Scan(1, "abc", ScanStatus.IN_PROGRESS, 0L, false))));
		Assertions.assertEquals(MergeGateOutcome.SCAN_IN_PROGRESS,
				classify(List.of(new Scan(1, "abc", ScanStatus.DONE, 12_000L, true))));
		Assertions.assertEquals(MergeGateOutcome.SCAN_IN_PROGRESS,
				classify(new MergedPullRequest(MERGED_AT, "abc", true), List.of(), List.of(),
						Set.of()), "queued when the merge was seen, then dropped");
	}

	@Test
	public void aFailedScanOfTheMergedCommitIsScanFailed() {
		Assertions.assertEquals(MergeGateOutcome.SCAN_FAILED,
				classify(List.of(new Scan(1, "abc", ScanStatus.FAILED, 9_000L, false))));
	}

	@Test
	public void onlyAnEarlierCommitScannedIsNewerCommitNotScanned() {
		Assertions.assertEquals(MergeGateOutcome.NEWER_COMMIT_NOT_SCANNED,
				classify(List.of(new Scan(1, "old", ScanStatus.DONE, 9_000L, false))));
	}

	@Test
	public void noScanAtAllIsNeverScanned() {
		Assertions.assertEquals(MergeGateOutcome.NEVER_SCANNED, classify(List.of()));
	}

	@Test
	public void withoutAMergedCommitAnyScanBeforeTheMergeCounts() {
		MergedPullRequest unknownCommit = new MergedPullRequest(MERGED_AT, null, false);
		Assertions.assertEquals(MergeGateOutcome.SCANNED_CLEAN, classify(unknownCommit,
				List.of(new Scan(1, "old", ScanStatus.DONE, 9_000L, false)), List.of(), Set.of()));
	}

	@Test
	public void ungatedMeansBeforeScanOrUnbypassedBlockers() {
		Assertions.assertFalse(MergeGateOutcome.SCANNED_CLEAN.isUngated());
		Assertions.assertFalse(MergeGateOutcome.BLOCKED_BYPASSED.isUngated());
		Assertions.assertTrue(MergeGateOutcome.BLOCKED_UNBYPASSED.isUngated());
		Assertions.assertTrue(MergeGateOutcome.NEVER_SCANNED.isUngated());
	}
}
