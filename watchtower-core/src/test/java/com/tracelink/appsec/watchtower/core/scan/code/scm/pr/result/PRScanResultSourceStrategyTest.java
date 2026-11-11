package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** A report says how the source was fetched, so the full-source threshold has a visible effect. */
class PRScanResultSourceStrategyTest {

	private static PRScanResult with(String strategy, int changed) {
		PRScanResult result = new PRScanResult();
		result.setSourceStrategy(strategy);
		result.setChangedFileCount(changed);
		return result;
	}

	@Test
	void fewChangedFilesAreReadOneByOne() {
		assertEquals("Read the 2 changed files one by one.", with("INDIVIDUAL_FILES", 2).getSourceStrategyText());
		assertEquals("Read the 1 changed file one by one.", with("INDIVIDUAL_FILES_PRUNED", 1).getSourceStrategyText());
	}

	@Test
	void manyChangedFilesDownloadTheWholeRepository() {
		String text = with("FULL_DOWNLOAD", 7).getSourceStrategyText();

		assertTrue(text.startsWith("Downloaded the whole repository because 7 changed files"), text);
		assertTrue(text.contains("threshold"));
	}

	@Test
	void cachedAndManifestStrategiesAreDescribedAndAnUnknownOneSaysNothing() {
		assertTrue(with("CACHED_ARCHIVE", 3).getSourceStrategyText().startsWith("Used a cached copy"));
		assertTrue(with("MANIFEST_FILES", 3).getSourceStrategyText().contains("dependency manifests"));
		assertNull(with("UNKNOWN", 3).getSourceStrategyText());
		assertNull(with(null, 3).getSourceStrategyText());
	}
}
