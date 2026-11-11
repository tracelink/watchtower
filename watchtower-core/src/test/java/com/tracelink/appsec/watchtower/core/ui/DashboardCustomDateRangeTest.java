package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

class DashboardCustomDateRangeTest {

	@Test
	void dashboardsUseOneSharedCustomDateOptionWithoutADuplicateAction() throws IOException {
		Path repoRoot = Path.of("..").toAbsolutePath().normalize();
		for (String template : List.of("pull_requests/dashboard.html",
				"upload_scan/dashboard.html", "image_scan/dashboard.html",
				"repo_scan/dashboard.html")) {
			String html = Files.readString(repoRoot.resolve(
					"watchtower-core/src/main/resources/templates/" + template));
			assertTrue(html.contains("fragments/dashboard :: insights"), template);
		}
		String fragment = Files.readString(repoRoot.resolve(
				"watchtower-core/src/main/resources/templates/fragments/dashboard.html"));
		assertEquals(0, occurrences(fragment, "data-custom-range-for="));
		// One Custom option on the shared range buttons; its From/To fields are made by utils.js.
		assertEquals(1, occurrences(fragment, "data-period=\"custom\""));
		assertEquals(1, occurrences(fragment, "data-custom-label>Custom</span>"));
		// The Kibana-style panel: quick ranges, From-To dates (which the metric query reads), Apply.
		assertEquals(10, occurrences(fragment, "data-quick=\""));
		assertTrue(fragment.contains("id=\"dashboard-period-custom-from\" type=\"date\""));
		assertTrue(fragment.contains("id=\"dashboard-period-custom-to\" type=\"date\""));
		assertTrue(fragment.contains("data-range-apply"));
	}

	@Test
	void generatedMaterialDateFieldsHaveLabelsAndErrorStatus() throws IOException {
		Path script = Path.of("..").toAbsolutePath().normalize().resolve(
				"watchtower-core/src/main/resources/static/scripts/dashboard/utils.js");
		String javascript = Files.readString(script);
		assertEquals(2, occurrences(javascript,
				"document.createElement('md-outlined-text-field')"));
		assertTrue(javascript.contains("fromInput.label = 'From'"));
		assertTrue(javascript.contains("toInput.label = 'To'"));
		assertTrue(javascript.contains("error.setAttribute('role', 'alert')"));
		assertTrue(javascript.contains("document.createElement('fieldset')"));
		assertTrue(!javascript.contains("range.innerHTML"));
	}

	private int occurrences(String value, String token) {
		return (value.length() - value.replace(token, "").length()) / token.length();
	}
}
