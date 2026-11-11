package com.tracelink.appsec.watchtower.core.cwe;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.Test;

/** What the Knowledge page chip says for each state of the catalog. */
class CweCatalogChipTest {
	private static final long LOADED = Instant.parse("2026-10-26T12:00:00Z").toEpochMilli();

	private static CweCatalogService.Status status(String state, String version, int count, String message, String progress) {
		return new CweCatalogService.Status(state, version, version == null ? null : "2026-04-30", count, message, progress,
				version == null ? null : LOADED, version == null ? null : "alice");
	}

	@Test
	void aLoadedCatalogShowsItsReleaseAndSize() {
		var chip = CweCatalogChip.of(status("OK", "4.20", 969, null, null));

		assertThat(chip.label()).isEqualTo("CWE 4.20 · 969");
		assertThat(chip.tone()).isEmpty();
		assertThat(chip.updating()).isFalse();
		assertThat(chip.tip()).contains("4.20", "30 Apr 2026", "969 weaknesses", "26 Oct 2026", "alice", "MITRE");
	}

	@Test
	void aCatalogThatWasNeverLoadedSaysHowToLoadIt() {
		var chip = CweCatalogChip.of(status("NEVER", null, 0, null, null));

		assertThat(chip.label()).isEqualTo("CWE catalog: not loaded");
		assertThat(chip.tone()).isEqualTo("warn");
		assertThat(chip.tip()).contains("update");
	}

	@Test
	void aFailedUpdateSaysWhyAndThatTheOldCatalogIsStillInUse() {
		var chip = CweCatalogChip.of(status("FAILED", "4.19", 960, "MITRE did not answer after 3 tries (HTTP 503)", null));

		assertThat(chip.label()).isEqualTo("CWE 4.19 · update failed");
		assertThat(chip.tone()).isEqualTo("warn");
		assertThat(chip.tip()).contains("503", "4.19", "still in use");
	}

	@Test
	void aFailedFirstLoadHasNothingToFallBackOn() {
		var chip = CweCatalogChip.of(status("FAILED", null, 0, "MITRE did not answer", null));

		assertThat(chip.label()).isEqualTo("CWE catalog: update failed");
		assertThat(chip.tip()).doesNotContain("still in use");
	}

	@Test
	void aRunningUpdateShowsItsProgress() {
		var chip = CweCatalogChip.of(status("UPDATING", "4.19", 960, null, "Downloading 40 of 969"));

		assertThat(chip.updating()).isTrue();
		assertThat(chip.label()).isEqualTo("Updating…");
		assertThat(chip.tip()).contains("Downloading 40 of 969");
		assertThat(chip.tone()).isEqualTo("info");
	}

	@Test
	void anUpdateWithNoProgressYetStillSaysItIsQueued() {
		assertThat(CweCatalogChip.of(status("UPDATING", null, 0, null, null)).tip()).contains("queued");
	}

	@Test
	void anErrorMessageIsShownAsPlainTextOnly() {
		var chip = CweCatalogChip.of(status("FAILED", "4.19", 960, "bad <script>alert(1)</script>\nnext line", null));

		assertThat(chip.tip()).doesNotContain("<script>");
	}
}
