package com.tracelink.appsec.watchtower.core.ruleset;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * A hash of what a module provides: its rulesets and every rule's content. Startup imports a
 * module's provided rules only when this changed since the last import, rather than rewriting
 * hundreds of unchanged rules on every boot.
 * <p>
 * Built from each rule's simple-valued fields (strings, numbers, booleans, enums, and
 * collections of those), found by reflection so a module's own rule fields count without the
 * module doing anything. Other fields are skipped: they are compiled from the simple ones (a
 * regex {@code Pattern}, a {@code JsonPath}). Lines are sorted, so set order does not matter.
 *
 * @author Watchtower
 */
public final class ProvidedRulesFingerprint {

	/**
	 * Part of every fingerprint. Raise it when importing changes in a way the rules' content
	 * does not show, so every module imports once more.
	 */
	static final int FORMAT_VERSION = 1;

	private ProvidedRulesFingerprint() {
	}

	/**
	 * @param rulesets a module's provided rulesets, named as they are stored
	 * @return a SHA-256 hex digest of their content
	 */
	public static String of(Collection<RulesetDto> rulesets) {
		List<String> lines = new ArrayList<>();
		lines.add("format|" + FORMAT_VERSION);
		for (RulesetDto ruleset : rulesets) {
			addRuleset(lines, ruleset);
		}
		lines.sort(null);
		return sha256(String.join("\n", lines));
	}

	private static void addRuleset(List<String> lines, RulesetDto ruleset) {
		String inherited = ruleset.getRulesets().stream().map(RulesetDto::getName)
				.sorted().collect(Collectors.joining(","));
		lines.add(String.join("|", "ruleset", ruleset.getName(), ruleset.getDescription(),
				String.valueOf(ruleset.getDesignation()),
				String.valueOf(ruleset.getBlockingLevel()), inherited));
		for (RuleDto rule : ruleset.getRules()) {
			lines.add("rule|" + ruleset.getName() + "|" + describe(rule));
		}
		for (RulesetDto child : ruleset.getRulesets()) {
			addRuleset(lines, child);
		}
	}

	/**
	 * @return the rule's class and its simple fields as sorted name=value pairs
	 */
	static String describe(RuleDto rule) {
		List<String> fields = new ArrayList<>();
		for (Class<?> type = rule.getClass(); type != null && type != Object.class;
				type = type.getSuperclass()) {
			for (Field field : type.getDeclaredFields()) {
				if (Modifier.isStatic(field.getModifiers()) || "id".equals(field.getName())) {
					continue;
				}
				String value = simpleValue(read(field, rule));
				if (value != null) {
					fields.add(type.getSimpleName() + "." + field.getName() + "=" + value);
				}
			}
		}
		fields.sort(null);
		return rule.getClass().getName() + "|" + String.join("|", fields);
	}

	private static Object read(Field field, Object owner) {
		try {
			field.setAccessible(true);
			return field.get(owner);
		} catch (ReflectiveOperationException | RuntimeException e) {
			throw new IllegalStateException("Cannot read rule field " + field.getName(), e);
		}
	}

	/**
	 * @return the value as text, "null" for null, or null if it is not a simple value
	 */
	private static String simpleValue(Object value) {
		if (value == null) {
			return "null";
		}
		if (value instanceof CharSequence || value instanceof Number
				|| value instanceof Boolean || value instanceof Character
				|| value instanceof Enum<?>) {
			// Lengths keep "a|b" + "c" apart from "a" + "b|c".
			String text = value.toString();
			return text.length() + ":" + text;
		}
		if (value instanceof Collection<?> collection) {
			List<String> items = collection.stream().map(ProvidedRulesFingerprint::simpleValue)
					.toList();
			if (items.stream().anyMatch(Objects::isNull)) {
				return null;
			}
			return "[" + items.stream().sorted().collect(Collectors.joining(",")) + "]";
		}
		return null;
	}

	private static String sha256(String text) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
					.digest(text.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is unavailable", e);
		}
	}
}
