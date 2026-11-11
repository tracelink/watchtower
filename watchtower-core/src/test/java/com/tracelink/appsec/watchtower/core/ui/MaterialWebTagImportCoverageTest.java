package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Material Web migration, Section D: a build-time-only check for the exact
 * class of bug the CDN pilot hit - a template reaching for an
 * {@code md-*} custom element whose defining module was never imported
 * (or, for the pilot's original bug, whose transitive dependency wasn't in
 * the import map), so the tag silently renders as unstyled inline content
 * instead of throwing.
 *
 * <p>{@code @material/web} names its component modules
 * {@code @material/web/<category>/<name>.js}, and each one registers
 * exactly the custom element {@code md-<name>} (e.g.
 * {@code @material/web/button/filled-button.js} registers
 * {@code md-filled-button}) - confirmed against the actual imports in
 * {@code material-web/src/index.js}. This test relies on that convention
 * holding to map an import line to the tag name it registers, rather than
 * requiring a real browser/jsdom to observe {@code customElements.get(...)}
 * the way {@code material-web/smoketest.js} does at build time - the two
 * checks are complementary: this one catches "forgot to import this tag" at
 * template-authoring time without needing the bundle rebuilt first;
 * {@code smoketest.js} catches "the import exists but registration still
 * failed" (the pilot's actual bug) after a real build.
 */
class MaterialWebTagImportCoverageTest {

	private static final String INDEX_JS_RELATIVE_PATH =
			"watchtower-core/src/main/frontend/material-web/src/index.js";

	private static final Pattern IMPORT_PATTERN =
			Pattern.compile("@material/web/[\\w-]+/([a-z][a-z-]*)\\.js");

	// Anchored on the opening '<' (optionally '</') - a bare \bmd-[a-z-]+\b with no anchor also
	// matches Bootstrap's '-md-' breakpoint infix (e.g. 'd-md-inline', 'd-md-none'), CSS custom
	// property names ('--md-sys-color-primary'), the md-theme.css filename in an href, and this
	// class's own doc comments mentioning a tag name - none of which are a real tag usage.
	// Requiring '<' immediately before is unambiguous: that character sequence only appears at
	// an actual (Thymeleaf-rendered) HTML tag open.
	private static final Pattern TAG_USAGE_PATTERN =
			Pattern.compile("</?(md-[a-z]+(?:-[a-z]+)*)");

	@Test
	void everyMdTagUsedInTemplatesHasAMatchingImport() throws IOException {
		Path repoRoot = TemplateModuleScanner.repoRoot();
		Set<String> registeredTags = registeredTags(repoRoot);
		assertTrue(!registeredTags.isEmpty(),
				"Parsed zero tag registrations out of " + INDEX_JS_RELATIVE_PATH
						+ " - the import-line regex or the file itself is likely broken, since "
						+ "the pilot alone registers 8 tags");

		List<String> failures = new ArrayList<>();
		for (Path relativeTemplate : TemplateModuleScanner.findAllTemplateFilesRelativeToRepoRoot()) {
			String content = Files.readString(repoRoot.resolve(relativeTemplate));
			Set<String> usedTags = new TreeSet<>();
			Matcher matcher = TAG_USAGE_PATTERN.matcher(content);
			while (matcher.find()) {
				usedTags.add(matcher.group(1));
			}
			for (String tag : usedTags) {
				if (!registeredTags.contains(tag)) {
					failures.add(relativeTemplate + ": uses '" + tag
							+ "' but no import in " + INDEX_JS_RELATIVE_PATH
							+ " registers it - it will render as unstyled inline content");
				}
			}
		}

		assertTrue(failures.isEmpty(),
				"Template(s) use a Material Web tag with no matching import:\n"
						+ String.join("\n", failures));
	}

	private static Set<String> registeredTags(Path repoRoot) throws IOException {
		String indexJs = Files.readString(repoRoot.resolve(INDEX_JS_RELATIVE_PATH));
		Set<String> tags = new HashSet<>();
		Matcher matcher = IMPORT_PATTERN.matcher(indexJs);
		while (matcher.find()) {
			tags.add("md-" + matcher.group(1));
		}
		return tags;
	}
}
