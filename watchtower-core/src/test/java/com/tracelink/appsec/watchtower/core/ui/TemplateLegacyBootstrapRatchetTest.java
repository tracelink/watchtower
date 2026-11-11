package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Ratchets down the legacy Bootstrap 4 constructs that Phase 11's codemod
 * deliberately left alone because they cannot be converted additively
 * (IMPROVEMENT_PLAN.md, Phase 11 REMAINING WORK, Section B). Each seeded
 * count is today's actual count for that file and token; a count may only
 * ever go down as migration waves hand-convert it, never up. When a token
 * in a file reaches 0, delete its entry here so a single reintroduced
 * occurrence trips the "unknown token in file" failure below rather than
 * being silently absorbed by a stale non-zero seed.
 *
 * <p>Seeded 2026-09-19 across all 52 templates in all 8 modules that ship
 * one (watchtower-core, the six watchtower-module-* designers, and
 * watchtower-web) - matching the occurrence table in IMPROVEMENT_PLAN.md
 * Section B exactly: close 25/15 files, form-row 26/10, form-inline 22/13,
 * selectpicker 12/6, btn-group-toggle 10/10.
 *
 * <p>Sections A+B landed 2026-09-19: all five constructs are now fully
 * converted repo-wide (see the close-button fragment, the .row/.d-flex
 * rewrites, the .form-select conversions, and the .btn-check radio-group
 * rewrite in reposwitcher.js/dashboard-stats-switcher.js). Every map below
 * is empty (bar one comment-text exception, see EXPECTED_SELECTPICKER) per
 * this class's own convention above - a single reintroduced occurrence of
 * any of these five tokens, anywhere, now fails this test.
 *
 * <p>Material Web migration, Section D: extended from {@code .html}-only to
 * also scan every module's {@code static/scripts/*.js} files
 * ({@link TemplateModuleScanner#findAllScriptFilesRelativeToRepoRoot()}).
 * Confirmed gap this closes: {@code advisory-designer.js} and
 * {@code eslint-designer.js} both emit Bootstrap markup
 * (data-toggle="modal", class='form-control') as raw JS strings for
 * DataTables-rendered rows - invisible to a scanner that only ever looked
 * at {@code .html} files. Deliberately not seeded with a new set of
 * Material-Web-era banned tokens (data-bs-toggle="modal", class="btn ,
 * class="form-control, col-, card-header) yet: doing that accurately for
 * hundreds of occurrences across 56 templates with no per-page conversion
 * work done yet would be a large, blind, error-prone count with no
 * verification loop - each Section E wave seeds/lowers its own files'
 * counts as it actually converts them (see that wave's own checklist step),
 * which is both more accurate and matches this file's own "seeded count is
 * today's actual count" convention.
 */
class TemplateLegacyBootstrapRatchetTest {

	private record BannedToken(String name, String literal, Map<String, Integer> expectedCountByFile) {
	}

	private static final Map<String, Integer> EXPECTED_CLOSE = Map.of();

	private static final Map<String, Integer> EXPECTED_FORM_ROW = Map.of();

	private static final Map<String, Integer> EXPECTED_FORM_INLINE = Map.of();

	// Was seeded at 1 for a comment in searchable-listbox.js narrating why that file existed -
	// Material Web migration Section C deleted the whole file (replaced by
	// wt-searchable-listbox.js), so per this class's own convention the entry is deleted too,
	// not left at a stale non-zero count for a file that no longer exists.
	private static final Map<String, Integer> EXPECTED_SELECTPICKER = Map.of();

	private static final Map<String, Integer> EXPECTED_BTN_GROUP_TOGGLE = Map.of();

	private static final List<BannedToken> BANNED_TOKENS = List.of(
			new BannedToken("close", "class=\"close\"", EXPECTED_CLOSE),
			new BannedToken("form-row", "form-row", EXPECTED_FORM_ROW),
			new BannedToken("form-inline", "form-inline", EXPECTED_FORM_INLINE),
			new BannedToken("selectpicker", "selectpicker", EXPECTED_SELECTPICKER),
			new BannedToken("btn-group-toggle", "btn-group-toggle", EXPECTED_BTN_GROUP_TOGGLE));

	@Test
	void legacyBootstrapTokenCountsNeverIncrease() throws IOException {
		Path repoRoot = TemplateModuleScanner.repoRoot();
		List<Path> filesToScan = new ArrayList<>();
		filesToScan.addAll(TemplateModuleScanner.findAllTemplateFilesRelativeToRepoRoot());
		filesToScan.addAll(TemplateModuleScanner.findAllScriptFilesRelativeToRepoRoot());
		List<String> failures = new ArrayList<>();

		for (BannedToken token : BANNED_TOKENS) {
			for (Path relativeFile : filesToScan) {
				String key = relativeFile.toString();
				int actualCount =
						countLiteralOccurrences(repoRoot.resolve(relativeFile), token.literal());
				Integer expectedCount = token.expectedCountByFile().get(key);

				if (expectedCount == null) {
					if (actualCount > 0) {
						failures.add(String.format(
								"%s: found %d occurrence(s) of '%s' in a file with no seeded "
										+ "count (new usage, or the file was renamed since seeding)",
								key, actualCount, token.name()));
					}
					continue;
				}

				if (actualCount > expectedCount) {
					failures.add(String.format(
							"%s: found %d occurrence(s) of '%s', expected at most %d - a "
									+ "regression reintroduced this legacy construct",
							key, actualCount, token.name(), expectedCount));
				}
			}
		}

		assertTrue(failures.isEmpty(),
				"Legacy Bootstrap 4 token count(s) increased beyond their seeded ceiling:\n"
						+ String.join("\n", failures));
	}

	private static int countLiteralOccurrences(Path file, String literal) throws IOException {
		String content = Files.readString(file);
		Pattern pattern = Pattern.compile(Pattern.quote(literal));
		Matcher matcher = pattern.matcher(content);
		int count = 0;
		while (matcher.find()) {
			count++;
		}
		return count;
	}
}
