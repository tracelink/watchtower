package com.tracelink.appsec.watchtower.core.scan.code;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Helpers for deciding whether a file is worth handing to a scanner.
 *
 * @author csmith
 */
public final class FileTypeUtils {

	/**
	 * Number of leading bytes sampled when deciding whether a file is binary. A header
	 * is enough - reading whole files would be wasteful on a large repository.
	 */
	private static final int SAMPLE_BYTES = 1000;

	/**
	 * Percentage of sampled bytes that must be printable for a file to count as text.
	 */
	private static final int PRINTABLE_PERCENT_THRESHOLD = 95;

	private FileTypeUtils() {
		// utility class
	}

	/**
	 * Determines whether a file is likely binary, by sampling its leading bytes and
	 * measuring how many are printable.
	 * <p>
	 * Extension blocklists miss compiled classes, minified bundles and binary assets
	 * saved under unexpected names, all of which produce scanner noise or outright
	 * scanner errors when fed in as source.
	 * <p>
	 * An empty file counts as text, since there is nothing to suggest otherwise. A file
	 * that cannot be read counts as binary, so unreadable content is skipped rather than
	 * scanned.
	 *
	 * @param file the file to inspect
	 * @return true if the file appears to be binary
	 */
	public static boolean isBinary(Path file) {
		int countPrintable = 0;
		int countNotPrintable = 0;
		int count;

		try (InputStream in = Files.newInputStream(file)) {
			byte[] bytes = new byte[SAMPLE_BYTES];
			count = in.read(bytes);
			for (int i = 0; i < count; i++) {
				byte b = bytes[i];
				if ((b > 31 && b < 127) || b == '\t' || b == '\n' || b == '\r' || b == '\f') {
					countPrintable++;
				} else {
					countNotPrintable++;
				}
			}
		} catch (IOException e) {
			return true;
		}
		if (count <= 0) {
			return false;
		}
		return (countPrintable * 100) / (countPrintable + countNotPrintable)
				< PRINTABLE_PERCENT_THRESHOLD;
	}
}
