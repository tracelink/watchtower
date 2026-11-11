package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

/**
 * Unit tests for the Material Web era assertions in {@link HtmlAssertions}, run directly
 * against hand-crafted HTML (not through MockMvc). The regex designer's own controller test
 * (the only place in the app rendering real md-dialog markup end to end today) mocks its
 * child designer view entirely, so it never actually exercises the real regex.html content
 * these assertions are meant to catch problems in - testing the assertion logic in isolation
 * here is more reliable than trying to force it through that mock.
 */
class HtmlAssertionsTest {

	@Test
	void assertAllWtDialogTargetsResolve_passesWhenTargetExists() {
		Document document = Jsoup.parse(
				"<button data-wt-dialog-target=\"#myDialog\">Open</button>"
						+ "<md-dialog id=\"myDialog\"></md-dialog>");
		assertDoesNotThrow(() -> HtmlAssertions.assertAllWtDialogTargetsResolve(document));
	}

	@Test
	void assertAllWtDialogTargetsResolve_failsWhenTargetMissing() {
		Document document = Jsoup.parse(
				"<button data-wt-dialog-target=\"#missingDialog\">Open</button>");
		assertThrows(AssertionFailedError.class,
				() -> HtmlAssertions.assertAllWtDialogTargetsResolve(document));
	}

	@Test
	void assertAllMdFieldsHaveAccessibleLabel_passesWithLabelAttribute() {
		Document document = Jsoup.parse("<md-outlined-text-field label=\"Rule Name\">"
				+ "</md-outlined-text-field>");
		assertDoesNotThrow(
				() -> HtmlAssertions.assertAllMdFieldsHaveAccessibleLabel(document));
	}

	@Test
	void assertAllMdFieldsHaveAccessibleLabel_failsWithNoLabelOrAriaLabel() {
		Document document = Jsoup.parse("<md-outlined-text-field></md-outlined-text-field>");
		assertThrows(AssertionFailedError.class,
				() -> HtmlAssertions.assertAllMdFieldsHaveAccessibleLabel(document));
	}

	@Test
	void assertAllMdFieldsHaveAccessibleLabel_checkboxPassesWithAncestorLabel() {
		Document document = Jsoup.parse(
				"<label><md-checkbox></md-checkbox> Manual Code Review Rule</label>");
		assertDoesNotThrow(
				() -> HtmlAssertions.assertAllMdFieldsHaveAccessibleLabel(document));
	}

	@Test
	void assertAllMdFieldsHaveAccessibleLabel_checkboxPassesWithAriaLabel() {
		Document document = Jsoup.parse("<md-checkbox aria-label=\"Manual Code Review Rule\">"
				+ "</md-checkbox>");
		assertDoesNotThrow(
				() -> HtmlAssertions.assertAllMdFieldsHaveAccessibleLabel(document));
	}

	@Test
	void assertAllMdFieldsHaveAccessibleLabel_checkboxFailsWithNeither() {
		Document document = Jsoup.parse("<md-checkbox></md-checkbox>");
		assertThrows(AssertionFailedError.class,
				() -> HtmlAssertions.assertAllMdFieldsHaveAccessibleLabel(document));
	}

	@Test
	void assertAllFormAttributesResolve_passesWhenFormExists() {
		Document document = Jsoup.parse("<form id=\"myForm\"></form>"
				+ "<md-filled-button form=\"myForm\">Save</md-filled-button>");
		assertDoesNotThrow(() -> HtmlAssertions.assertAllFormAttributesResolve(document));
	}

	@Test
	void assertAllFormAttributesResolve_failsWhenFormMissing() {
		Document document = Jsoup.parse(
				"<md-filled-button form=\"missingForm\">Save</md-filled-button>");
		assertThrows(AssertionFailedError.class,
				() -> HtmlAssertions.assertAllFormAttributesResolve(document));
	}
}
