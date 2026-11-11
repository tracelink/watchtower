package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class PullRequestMCRControllerTest {

	@Test
	void mcrLandingPageDefaultsToAllMcrs() {
		PullRequestMCRController controller = new PullRequestMCRController(null);

		assertEquals("redirect:/scan/mcr/all", controller.getResultsHome().getViewName());
	}
}
