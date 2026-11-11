package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.test.web.servlet.MvcResult;

/**
 * HTML-structure assertions run against a MockMvc-rendered Thymeleaf page
 * (IMPROVEMENT_PLAN.md, Phase 11 REMAINING WORK, Safety net I, third bullet).
 * A test opts in by calling {@link #assertHtmlIntegrity(MvcResult)} - or one
 * of the individual checks - on the {@link MvcResult} of a
 * {@code mockMvc.perform(...).andReturn()} call.
 *
 * <p>These catch structural defects that a Thymeleaf template can render
 * without error but that break at the browser: two elements sharing an id
 * (breaks {@code getElementById}, ARIA references, and any
 * {@code label[for]}), a Bootstrap trigger pointing at a
 * {@code data-bs-target} that does not exist (the plan's own
 * {@code #myModal}/{@code #createModal}/{@code #deleteModal} id-collision
 * risk across copy-pasted modals), or a {@code <label for>} with no matching
 * field.
 *
 * <p>Material Web migration additions: a {@code data-wt-dialog-target} that
 * does not resolve (the {@code md-dialog} equivalent of a broken
 * {@code data-bs-target}, since {@code md-dialog} has no declarative
 * open-trigger attribute of its own), a Material Web field/checkbox/radio
 * with no accessible name, and a {@code form="x"} attribute that does not
 * resolve to a real {@code <form id="x">} (form-associated custom elements,
 * e.g. a dialog's actions-slot button submitting a form it is not a DOM
 * descendant of).
 *
 * <p>A response with no HTML body (a redirect, a JSON payload, an empty
 * body) parses to zero matches for every check and passes vacuously - these
 * assertions are only meaningful when called against a real rendered page.
 */
public final class HtmlAssertions {

	private HtmlAssertions() {
	}

	/**
	 * Runs all structural checks against the given result's rendered body,
	 * Bootstrap-era and Material-Web-era alike.
	 */
	public static void assertHtmlIntegrity(MvcResult result) throws Exception {
		Document document = parse(result);
		assertNoDuplicateIds(document);
		assertAllDataBsTargetsResolve(document);
		assertAllLabelForsResolve(document);
		assertAllWtDialogTargetsResolve(document);
		assertAllMdFieldsHaveAccessibleLabel(document);
		assertAllFormAttributesResolve(document);
	}

	public static void assertNoDuplicateIds(MvcResult result) throws Exception {
		assertNoDuplicateIds(parse(result));
	}

	public static void assertAllDataBsTargetsResolve(MvcResult result) throws Exception {
		assertAllDataBsTargetsResolve(parse(result));
	}

	public static void assertAllLabelForsResolve(MvcResult result) throws Exception {
		assertAllLabelForsResolve(parse(result));
	}

	public static void assertAllWtDialogTargetsResolve(MvcResult result) throws Exception {
		assertAllWtDialogTargetsResolve(parse(result));
	}

	public static void assertAllMdFieldsHaveAccessibleLabel(MvcResult result) throws Exception {
		assertAllMdFieldsHaveAccessibleLabel(parse(result));
	}

	public static void assertAllFormAttributesResolve(MvcResult result) throws Exception {
		assertAllFormAttributesResolve(parse(result));
	}

	private static Document parse(MvcResult result) throws Exception {
		String html = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
		return Jsoup.parse(html);
	}

	/**
	 * Two elements sharing an id on the same rendered page breaks
	 * {@code getElementById}, ARIA {@code aria-*} id references, and
	 * {@code label[for]} resolution. This is a within-page check - the
	 * plan's {@code #myModal}/{@code #createModal}/{@code #deleteModal}
	 * pattern reused *across different pages* is fine, since only one of
	 * those pages is ever rendered into a single document at a time.
	 */
	private static void assertNoDuplicateIds(Document document) {
		Map<String, Integer> countById = new HashMap<>();
		for (Element element : document.select("[id]")) {
			String id = element.id();
			if (!id.isEmpty()) {
				countById.merge(id, 1, Integer::sum);
			}
		}
		List<String> duplicates = new ArrayList<>();
		for (Map.Entry<String, Integer> entry : countById.entrySet()) {
			if (entry.getValue() > 1) {
				duplicates.add(entry.getKey() + " (" + entry.getValue() + " occurrences)");
			}
		}
		assertTrue(duplicates.isEmpty(),
				"Duplicate id(s) found in rendered HTML - this breaks getElementById, ARIA id "
						+ "references and label[for] resolution for every id after the first:\n"
						+ String.join("\n", duplicates));
	}

	/**
	 * Every {@code data-bs-target="#x"} must point at an id that exists in
	 * the same document, or the Bootstrap component it triggers (modal,
	 * collapse, tab, etc.) silently does nothing when clicked.
	 */
	private static void assertAllDataBsTargetsResolve(Document document) {
		Set<String> ids = idsOf(document);
		List<String> unresolved = new ArrayList<>();
		for (Element element : document.select("[data-bs-target]")) {
			String target = element.attr("data-bs-target");
			if (target.startsWith("#")) {
				String targetId = target.substring(1);
				if (!ids.contains(targetId)) {
					unresolved.add(target + " (from " + element.tagName() + " "
							+ element.outerHtml().lines().findFirst().orElse("") + ")");
				}
			}
		}
		assertTrue(unresolved.isEmpty(),
				"data-bs-target(s) with no matching id in the rendered HTML - the Bootstrap "
						+ "component silently does nothing when triggered:\n"
						+ String.join("\n", unresolved));
	}

	/**
	 * Every {@code <label for="x">} must point at an id that exists in the
	 * same document, or clicking/tapping the label does not focus the
	 * intended field and screen readers cannot associate the two.
	 */
	private static void assertAllLabelForsResolve(Document document) {
		Set<String> ids = idsOf(document);
		List<String> unresolved = new ArrayList<>();
		Elements labels = document.select("label[for]");
		for (Element label : labels) {
			String forId = label.attr("for");
			if (!forId.isEmpty() && !ids.contains(forId)) {
				unresolved.add("for=\"" + forId + "\" (label text: \"" + label.text() + "\")");
			}
		}
		assertTrue(unresolved.isEmpty(),
				"label[for] attribute(s) with no matching id in the rendered HTML - the label "
						+ "does not focus its field and is not associated with it for assistive "
						+ "technology:\n" + String.join("\n", unresolved));
	}

	/**
	 * Material Web migration: {@code md-dialog} has no declarative
	 * open-trigger attribute the way {@code data-bs-target} was for
	 * Bootstrap modals - a trigger opens it imperatively via JS
	 * ({@code dialog.show()}). To keep that link statically checkable the
	 * same way {@link #assertAllDataBsTargetsResolve(Document)} checks
	 * Bootstrap triggers, every dialog-open trigger carries a
	 * {@code data-wt-dialog-target="#dialogId"} attribute purely for this
	 * assertion's benefit - the JS itself also reads it (see
	 * {@code regex-designer.js}), so the attribute is load-bearing, not
	 * decorative.
	 */
	// Package-private (not private): HtmlAssertionsTest exercises these directly against
	// hand-crafted HTML, since the only real md-dialog markup in the app today is rendered by
	// a controller test that mocks its child designer view entirely (see that test's own
	// comment) and so never actually renders the real regex.html content this method checks.
	static void assertAllWtDialogTargetsResolve(Document document) {
		Set<String> ids = idsOf(document);
		List<String> unresolved = new ArrayList<>();
		for (Element element : document.select("[data-wt-dialog-target]")) {
			String target = element.attr("data-wt-dialog-target");
			if (target.startsWith("#")) {
				String targetId = target.substring(1);
				if (!ids.contains(targetId)) {
					unresolved.add(target + " (from " + element.tagName() + " "
							+ element.outerHtml().lines().findFirst().orElse("") + ")");
				}
			}
		}
		assertTrue(unresolved.isEmpty(),
				"data-wt-dialog-target(s) with no matching id in the rendered HTML - the dialog "
						+ "trigger silently does nothing when clicked:\n"
						+ String.join("\n", unresolved));
	}

	/**
	 * Material Web text fields/selects take their accessible name from a
	 * {@code label} (or {@code aria-label}) attribute on the element itself,
	 * not a separate {@code <label for>} - {@link #assertAllLabelForsResolve}
	 * does not cover them at all. Checkboxes/radios have no {@code label}
	 * attribute of their own; their accessible name comes from an ancestor
	 * {@code <label>} (the pattern the regex designer pilot uses:
	 * {@code <label><md-checkbox/> text</label>}) or an explicit
	 * {@code aria-label}.
	 */
	static void assertAllMdFieldsHaveAccessibleLabel(Document document) {
		List<String> unlabeled = new ArrayList<>();
		for (Element field : document.select(
				"md-outlined-text-field, md-filled-text-field, md-outlined-select, md-filled-select")) {
			boolean hasLabel = !field.attr("label").isEmpty() || !field.attr("aria-label").isEmpty();
			if (!hasLabel) {
				unlabeled.add(field.outerHtml().lines().findFirst().orElse(""));
			}
		}
		for (Element field : document.select("md-checkbox, md-radio")) {
			boolean hasAriaLabel = !field.attr("aria-label").isEmpty();
			boolean hasAncestorLabel = field.parents().stream()
					.anyMatch(parent -> "label".equals(parent.tagName()));
			if (!hasAriaLabel && !hasAncestorLabel) {
				unlabeled.add(field.outerHtml().lines().findFirst().orElse(""));
			}
		}
		assertTrue(unlabeled.isEmpty(),
				"Material Web field(s) with no accessible name (no label/aria-label attribute, "
						+ "and for checkbox/radio no ancestor <label>) - a screen reader cannot "
						+ "announce what the field is for:\n" + String.join("\n", unlabeled));
	}

	/**
	 * Generalizes {@link #assertAllLabelForsResolve} to form-associated
	 * custom elements: a Material Web button or field can carry a
	 * {@code form="x"} attribute to submit/associate with a
	 * {@code <form>} it is not a DOM descendant of (the pilot's dialog
	 * actions slot lives outside the {@code <form>} its content slot
	 * wraps). If the referenced form id does not exist, the element is
	 * simply not associated with any form and its value/click never
	 * reaches a submission.
	 */
	static void assertAllFormAttributesResolve(Document document) {
		Set<String> ids = idsOf(document);
		List<String> unresolved = new ArrayList<>();
		for (Element element : document.select("[form]")) {
			String formId = element.attr("form");
			if (!formId.isEmpty() && !ids.contains(formId)) {
				unresolved.add("form=\"" + formId + "\" (from " + element.tagName() + " "
						+ element.outerHtml().lines().findFirst().orElse("") + ")");
			}
		}
		assertTrue(unresolved.isEmpty(),
				"form=\"...\" attribute(s) with no matching <form id> in the rendered HTML - the "
						+ "element is not associated with any form:\n"
						+ String.join("\n", unresolved));
	}

	private static Set<String> idsOf(Document document) {
		Set<String> ids = new HashSet<>();
		for (Element element : document.select("[id]")) {
			ids.add(element.id());
		}
		return ids;
	}
}
