package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

/**
 * Guards the full-page login redirect used when an htmx request discovers
 * that the user's session has expired.
 */
class HtmxSessionRedirectTest {

	@Test
	void loginResponseFromHtmxRequestTriggersFullPageNavigation() throws IOException {
		Path repoRoot = TemplateModuleScanner.repoRoot();
		Path scriptPath = repoRoot.resolve(
				"watchtower-core/src/main/resources/static/scripts/loading-indicator.js");
		Path headPath = repoRoot.resolve(
				"watchtower-core/src/main/resources/templates/fragments/htmlhead.html");
		String script = Files.readString(scriptPath);
		String head = Files.readString(headPath);

		assertTrue(head.contains("/scripts/loading-indicator.js"),
				"The global htmx lifecycle script must be loaded on every application page");
		assertTrue(script.contains("xhr.responseURL"),
				"The handler must inspect the final URL after Spring Security redirects");
		assertTrue(script.contains("responseUrl.pathname.endsWith('/login')"),
				"The handler must recognize the login page under any application context path");
		assertTrue(script.contains("event.detail.shouldSwap = false"),
				"The stale application fragment must not be swapped after session expiry");
		assertTrue(script.contains("window.location.replace(responseUrl.href)"),
				"The login page must replace the expired application shell with a full navigation");
	}
}
