package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

/**
 * Repository labels group repositories by business or function (for example {@code payments},
 * {@code pci}). They are stored in one column as {@code ,a,b,} - sorted, lowercase, comma
 * bracketed - so a filter for one label is an exact {@code LIKE '%,a,%'} with no join table.
 *
 * @author Watchtower
 */
public final class RepoLabels {

	public static final int MAX_LABELS = 10;

	private static final Pattern LABEL = Pattern.compile("[a-z0-9][a-z0-9-]{0,31}");

	private RepoLabels() {
	}

	/**
	 * @param labels labels as entered; blank entries are ignored, case is folded, duplicates
	 *               collapse
	 * @return the stored form, or null if there are no labels
	 * @throws IllegalArgumentException if a label is not 1-32 of {@code a-z 0-9 -} starting with
	 *                                  a letter or digit, or there are more than
	 *                                  {@value #MAX_LABELS}
	 */
	public static String format(Collection<String> labels) {
		if (labels == null) {
			return null;
		}
		TreeSet<String> normalised = new TreeSet<>();
		for (String label : labels) {
			String value = StringUtils.trimToEmpty(label).toLowerCase(Locale.ROOT);
			if (value.isEmpty()) {
				continue;
			}
			if (!LABEL.matcher(value).matches()) {
				throw new IllegalArgumentException("Label '" + StringUtils.abbreviate(value, 40)
						+ "' must be 1-32 letters, digits or hyphens");
			}
			normalised.add(value);
		}
		if (normalised.size() > MAX_LABELS) {
			throw new IllegalArgumentException(
					"A repository can have at most " + MAX_LABELS + " labels");
		}
		return normalised.isEmpty() ? null : "," + String.join(",", normalised) + ",";
	}

	/**
	 * @param stored the stored form, may be null
	 * @return the labels, sorted; empty if none
	 */
	public static List<String> parse(String stored) {
		if (StringUtils.isBlank(stored)) {
			return List.of();
		}
		return Arrays.stream(stored.split(",")).filter(StringUtils::isNotBlank).sorted()
				.toList();
	}

	/**
	 * @param input a comma or whitespace separated list, as typed in a form
	 * @return the individual labels, unvalidated
	 */
	public static List<String> split(String input) {
		if (StringUtils.isBlank(input)) {
			return List.of();
		}
		return Arrays.stream(input.trim().split("[,\\s]+")).filter(StringUtils::isNotBlank)
				.toList();
	}

	/**
	 * @param label one label, already validated
	 * @return the LIKE pattern matching repositories that carry exactly this label
	 */
	public static String likePattern(String label) {
		return "%," + label.toLowerCase(Locale.ROOT) + ",%";
	}
}
