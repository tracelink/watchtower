package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;

import org.junit.jupiter.api.Test;

/** The review status as the report shows it: an icon, a colour and a sentence, and the stored order. */
class PullRequestMCRStatusTest {
	private static final Set<String> TONES = Set.of("neutral", "warning", "info", "success");

	@Test
	void everyStatusHasAnIconAColourFromTheReportPaletteAndAMeaning() {
		for (PullRequestMCRStatus status : PullRequestMCRStatus.values()) {
			assertThat(status.getIcon()).as(status + " icon").isNotBlank();
			assertThat(status.getTone()).as(status + " tone").isIn(TONES);
			assertThat(status.getMeaning()).as(status + " meaning").isNotBlank();
		}
	}

	@Test
	void theStoredOrderIsUnchangedBecauseTheOrdinalIsWhatTheDatabaseHolds() {
		var converter = new PullRequestMCRStatus.PullRequestMCRStatusConverter();

		assertThat(PullRequestMCRStatus.values()).containsExactly(PullRequestMCRStatus.NOT_APPLICABLE, PullRequestMCRStatus.PENDING_REVIEW,
				PullRequestMCRStatus.IN_PROGRESS, PullRequestMCRStatus.REVIEWED, PullRequestMCRStatus.RECOMMENDATIONS);
		assertThat(converter.convertToDatabaseColumn(PullRequestMCRStatus.IN_PROGRESS)).isEqualTo("2");
		assertThat(converter.convertToEntityAttribute("4")).isEqualTo(PullRequestMCRStatus.RECOMMENDATIONS);
	}

	@Test
	void aStatusNameFromTheFormIsMatchedAndAnythingElseIsNot() {
		assertThat(PullRequestMCRStatus.enumStringToStatus("REVIEWED")).isEqualTo(PullRequestMCRStatus.REVIEWED);
		assertThat(PullRequestMCRStatus.enumStringToStatus("Reviewed")).isNull();
		assertThat(PullRequestMCRStatus.enumStringToStatus(null)).isNull();
	}
}
