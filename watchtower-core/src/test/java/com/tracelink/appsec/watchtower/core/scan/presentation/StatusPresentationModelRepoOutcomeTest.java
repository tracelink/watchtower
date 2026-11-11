package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanOutcome;

/** A repository scan that ended without scanning must not read as a finished scan of the code. */
class StatusPresentationModelRepoOutcomeTest {

	private static RepoScanEntity done(RepoScanOutcome outcome) {
		RepoScanEntity scan = new RepoScanEntity();
		scan.setStatus(ScanStatus.DONE);
		scan.setOutcome(outcome);
		return scan;
	}

	@Test
	void aMissingBranchIsNotScanned() {
		var status = StatusPresentationModel.from(done(RepoScanOutcome.BRANCH_MISSING));

		assertEquals("Not scanned", status.getLabel());
		assertTrue(status.getAccessibleText().contains("branch was not found"));
		assertTrue(status.isProcessingCompleted());
	}

	@Test
	void aRepositoryOverTheSizeLimitAndAStaleOneAreNotScanned() {
		assertEquals("Not scanned", StatusPresentationModel.from(done(RepoScanOutcome.SKIPPED_SIZE)).getLabel());
		assertEquals("Not scanned", StatusPresentationModel.from(done(RepoScanOutcome.SKIPPED_STALE)).getLabel());
	}

	@Test
	void aScannedOrUnchangedRepositoryKeepsItsOwnStatus() {
		assertNotEquals("Not scanned", StatusPresentationModel.from(done(RepoScanOutcome.SCANNED)).getLabel());
		assertNotEquals("Not scanned", StatusPresentationModel.from(done(RepoScanOutcome.UNCHANGED)).getLabel());
		assertNotEquals("Not scanned", StatusPresentationModel.from(done(null)).getLabel());
	}
}
