package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Every form control and icon-only button in every module's templates has an accessible name
 * (UAT #43): an aria-label, a Material label attribute, a wrapping label or a label for its id.
 * Controls hidden from assistive technology (aria-hidden) are skipped.
 */
class AccessibleNamesTest {
	private static final Pattern COMMENT = Pattern.compile("<!--.*?-->", Pattern.DOTALL);
	private static final Pattern CONTROL = Pattern.compile(
			"<(md-checkbox|input|select|textarea|md-switch|md-radio)\\b([^>]*)>", Pattern.DOTALL);
	private static final Pattern NAMED = Pattern.compile(
			"\\b(th:)?aria-label(ledby)?=|\\blabel=|th:label=|th:attr=\"[^\"]*aria-label");
	private static final Pattern ID = Pattern.compile("\\bid=\"([^\"]+)\"");
	private static final Pattern ICON_ONLY = Pattern.compile(
			"<(button|a|md-icon-button|md-text-button|md-outlined-button|summary)\\b([^>]*)>(.*?)</\\1>", Pattern.DOTALL);

	@Test
	void everyControlHasAnAccessibleName() throws IOException {
		List<String> unnamed = new ArrayList<>();
		for (Path template : TemplateModuleScanner.findAllTemplateFiles()) {
			String html = COMMENT.matcher(Files.readString(template)).replaceAll("");
			Matcher control = CONTROL.matcher(html);
			while (control.find()) {
				if (!named(html, control)) {
					unnamed.add(template.getFileName() + ": <" + control.group(1) + abbreviate(control.group(2)));
				}
			}
			Matcher button = ICON_ONLY.matcher(html);
			while (button.find()) {
				if (iconOnlyWithoutName(button)) {
					unnamed.add(template.getFileName() + ": icon-only <" + button.group(1) + abbreviate(button.group(2)));
				}
			}
		}
		assertEquals(List.of(), unnamed, "Give these controls an aria-label or a label");
	}

	private static boolean named(String html, Matcher control) {
		String tag = control.group(1);
		String attrs = control.group(2);
		if (tag.equals("input") && attrs.matches("(?s).*type=\"(hidden|submit|button)\".*")
				|| attrs.contains("aria-hidden=\"true\"") || NAMED.matcher(attrs).find()) {
			return true;
		}
		Matcher id = ID.matcher(attrs);
		if (id.find() && html.contains("for=\"" + id.group(1) + "\"")) {
			return true;
		}
		String before = html.substring(0, control.start());
		return before.lastIndexOf("<label") > before.lastIndexOf("</label>");
	}

	private static boolean iconOnlyWithoutName(Matcher button) {
		String attrs = button.group(2);
		String body = button.group(3);
		if (attrs.matches("(?s).*(aria-label|title=|th:title|th:attr=\"[^\"]*aria-label).*")
				|| !body.contains("material-icons") || body.contains("th:text") || body.contains("th:utext")) {
			return false;
		}
		String text = body.replaceAll("(?s)<span[^>]*material-icons[^>]*>.*?</span>", "").replaceAll("<[^>]+>", "").strip();
		return text.isEmpty();
	}

	private static String abbreviate(String attrs) {
		String flat = attrs.replaceAll("\\s+", " ").strip();
		return " " + (flat.length() > 80 ? flat.substring(0, 80) + "…" : flat) + ">";
	}
}
