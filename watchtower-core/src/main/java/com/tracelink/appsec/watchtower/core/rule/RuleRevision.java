package com.tracelink.appsec.watchtower.core.rule;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Versioned, deterministic SHA-256 encoding of an engine's managed definition. Callers explicitly
 * choose executable fields; DTO serialization, database ids and stewardship never enter the hash.
 * Strings are exact UTF-8 (no whitespace rewriting), with lengths and null markers so delimiters
 * inside code cannot make two definitions indistinguishable. Engine version/configuration is a
 * separate execution attribute, especially for rules whose implementation lives in the engine.
 */
public final class RuleRevision {

	private final Map<String, List<String>> fields = new TreeMap<>();

	private RuleRevision(String module, String designation) {
		field("module", module);
		field("designation", designation);
	}

	public static RuleRevision definition(String module, String designation) {
		return new RuleRevision(module, designation);
	}

	public RuleRevision field(String key, String value) {
		put(key, Collections.singletonList(value));
		return this;
	}

	/** For sets of parameters where database collection order has no meaning. */
	public RuleRevision unordered(String key, Collection<String> values) {
		put(key, values == null ? null : values.stream()
				.sorted(Comparator.nullsFirst(Comparator.naturalOrder())).toList());
		return this;
	}

	private void put(String key, List<String> values) {
		Objects.requireNonNull(key, "Definition field name is required");
		if (fields.containsKey(key)) {
			throw new IllegalArgumentException("Duplicate definition field");
		}
		fields.put(key, values);
	}

	public String hash() {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			append(digest, "watchtower-rule-definition-v1");
			appendInt(digest, fields.size());
			fields.forEach((key, values) -> {
				append(digest, key);
				appendInt(digest, values == null ? -1 : values.size());
				if (values != null) {
					values.forEach(value -> append(digest, value));
				}
			});
			return HexFormat.of().formatHex(digest.digest());
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is unavailable", e);
		}
	}

	private static void append(MessageDigest digest, String value) {
		if (value == null) {
			appendInt(digest, -1);
			return;
		}
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		appendInt(digest, bytes.length);
		digest.update(bytes);
	}

	private static void appendInt(MessageDigest digest, int value) {
		digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value).array());
	}
}
