package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.junit.jupiter.api.Test;

/**
 * The Cmd+K command palette ({@code <wt-command-palette>}) depends on
 * living outside {@code #content} in {@code fragments/container.html} - the
 * same tier as {@code <wt-mobile-drawer>} - so that a boosted (htmx) internal
 * navigation never destroys and re-creates it, which would drop its global
 * keydown listener. This is a plain structural placement with no
 * compiler/runtime check behind it - a regression guard against someone
 * moving it inside {@code #content} (e.g. while restructuring the layout)
 * without noticing the listener-lifecycle assumption it would silently break.
 */
class CommandPaletteMarkupTest {

	@Test
	void commandPaletteRendersExactlyOnceOutsideContent() throws IOException {
		Path repoRoot = TemplateModuleScanner.repoRoot();
		String html = Files.readString(
				repoRoot.resolve("watchtower-core/src/main/resources/templates/fragments/container.html"));
		Document document = Jsoup.parse(html);

		Elements palettes = document.select("wt-command-palette");
		assertEquals(1, palettes.size(),
				"expected exactly one <wt-command-palette> in fragments/container.html");

		Element palette = palettes.first();
		assertNull(palette.closest("#content"),
				"<wt-command-palette> must live outside #content, or it will be destroyed and "
						+ "recreated on every boosted navigation, dropping its global keydown listener");
	}
}
