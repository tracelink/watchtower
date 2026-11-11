package com.tracelink.appsec.watchtower.core.rule.candidate;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class RuleCandidateControllerReasonTest {
	@Test
	void aRefusalNamesWhatIsWrong() {
		assertEquals("Select a saved example.",
				RuleCandidateController.reasonFor(new IllegalArgumentException("Select a saved example")));
	}

	@Test
	void aMissingOrOverlongMessageFallsBackToTheGeneralSentence() {
		String general = "Check the exact rule revision, authored fields and reviewed fixture references.";
		assertEquals(general, RuleCandidateController.reasonFor(new IllegalArgumentException()));
		assertEquals(general, RuleCandidateController.reasonFor(new IllegalArgumentException("x".repeat(300))));
	}
}
