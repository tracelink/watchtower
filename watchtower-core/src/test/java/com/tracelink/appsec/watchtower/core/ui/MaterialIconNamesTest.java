package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

/**
 * Every Material Icons name in a template must exist in the bundled font
 * (static/fonts/MaterialIcons-Regular.woff2, material-icons 1.13.12). A name outside it, such as
 * the Symbols-only "deployed_code", is not a glyph: the browser draws its letters with blank
 * glyphs, so the icon is missing and leaves a wide gap. material-icons-names.txt lists the font's
 * names (from the package's _data/versions.json).
 */
class MaterialIconNamesTest {

	private static final String CODEPOINTS = "material-icons-names.txt";

	/** The text of an element whose class includes material-icons. */
	private static final Pattern ICON_TEXT = Pattern.compile(
			"class=\"[^\"]*\\bmaterial-icons\\b[^\"]*\"[^>]*>\\s*([a-z0-9_]+)\\s*<");

	/** Quoted names in a th:text on a material-icons element, e.g. ${a ? 'x' : 'y'}. */
	private static final Pattern ICON_TH_TEXT = Pattern.compile(
			"class=\"[^\"]*\\bmaterial-icons\\b[^\"]*\"[^>]*th:text=\"([^\"]*)\"");
	private static final Pattern QUOTED = Pattern.compile("'([a-z0-9_]+)'");

	@Test
	void everyTemplateIconExistsInTheBundledFont() throws IOException {
		Set<String> font = fontIconNames();
		List<String> missing = new ArrayList<>();
		for (Path template : TemplateModuleScanner.findAllTemplateFiles()) {
			String source = Files.readString(template);
			Matcher text = ICON_TEXT.matcher(source);
			while (text.find()) {
				check(font, text.group(1), template, missing);
			}
			Matcher thText = ICON_TH_TEXT.matcher(source);
			while (thText.find()) {
				Matcher quoted = QUOTED.matcher(thText.group(1));
				while (quoted.find()) {
					check(font, quoted.group(1), template, missing);
				}
			}
		}
		assertTrue(missing.isEmpty(), "Icons not in the bundled Material Icons font: " + missing);
	}

	private static void check(Set<String> font, String name, Path template, List<String> missing) {
		if (!font.contains(name)) {
			missing.add(name + " (" + TemplateModuleScanner.repoRoot().relativize(template) + ")");
		}
	}

	private static Set<String> fontIconNames() throws IOException {
		try (InputStream in = MaterialIconNamesTest.class.getClassLoader()
				.getResourceAsStream(CODEPOINTS)) {
			assertNotNull(in, "material-icons-names.txt is on the test classpath");
			return new String(in.readAllBytes(), StandardCharsets.UTF_8).lines()
					.map(line -> line.split(" ")[0]).collect(Collectors.toSet());
		}
	}
}
