package com.tracelink.appsec.watchtower.core.cwe;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;

/**
 * What the Knowledge page shows for the CWE catalog: one chip with a short label, a longer hover text, an icon
 * and a tone. Built here once so the page and the status endpoint always say the same thing.
 *
 * @param state    NEVER, OK, FAILED or UPDATING
 * @param label    the chip text
 * @param tip      the hover text; plain text, lines separated by newlines
 * @param icon     a Material icon name
 * @param tone     {@code ""}, {@code warn} or {@code info}
 * @param updating whether an update is queued or running
 */
public record CweCatalogChip(String state, String label, String tip, String icon, String tone, boolean updating) {
	private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("d MMM uuuu", Locale.ENGLISH);
	private static final String TRADEMARK = "CWE™ is a trademark of The MITRE Corporation.";
	private static final int MAX_MESSAGE = 200;

	public static CweCatalogChip of(CweCatalogService.Status status) {
		boolean stored = status.version() != null && status.count() > 0;
		String loaded = status.version() == null ? null : "CWE " + status.version() + " · " + status.count();
		return switch (status.state()) {
			case "OK" -> new CweCatalogChip("OK", loaded, okTip(status), "menu_book", "", false);
			case "FAILED" -> failed(status, stored);
			case "UPDATING" -> new CweCatalogChip("UPDATING", "Updating…", updatingTip(status), "sync", "info", true);
			default -> new CweCatalogChip("NEVER", "CWE catalog: not loaded",
					"No CWE catalog yet. Press the update button to download it from MITRE.", "menu_book", "warn", false);
		};
	}

	private static CweCatalogChip failed(CweCatalogService.Status status, boolean stored) {
		String reason = "The last update failed: " + plain(status.message());
		if (!stored) {
			return new CweCatalogChip("FAILED", "CWE catalog: update failed", reason, "warning", "warn", false);
		}
		return new CweCatalogChip("FAILED", "CWE " + status.version() + " · update failed",
				reason + "\nThe previous catalog (" + status.version() + ") is still in use. Nothing was lost.", "warning", "warn",
				false);
	}

	private static String okTip(CweCatalogService.Status status) {
		String loaded = status.fetchedAt() == null ? ""
				: " · loaded " + DAY.format(Instant.ofEpochMilli(status.fetchedAt()).atZone(ZoneOffset.UTC))
						+ (status.by() == null ? "" : " by " + plain(status.by()));
		return "CWE catalog " + status.version() + " (" + day(status.date()) + ")\n" + status.count() + " weaknesses" + loaded
				+ "\n" + TRADEMARK;
	}

	private static String updatingTip(CweCatalogService.Status status) {
		return status.progress() == null ? "The update is queued." : "Updating from MITRE: " + plain(status.progress())
				+ ". You can leave this page.";
	}

	private static String day(String isoDate) {
		try {
			return DAY.format(LocalDate.parse(isoDate));
		} catch (DateTimeParseException | NullPointerException e) {
			return String.valueOf(isoDate);
		}
	}

	/** One line of text with no markup characters, so it is safe to show wherever it lands. */
	private static String plain(String text) {
		if (text == null) {
			return "no reason given";
		}
		String line = text.replaceAll("<[^>]*>", "").replaceAll("\\p{Cntrl}", " ").replaceAll("\\s+", " ").strip();
		return line.length() > MAX_MESSAGE ? line.substring(0, MAX_MESSAGE) : line;
	}
}
