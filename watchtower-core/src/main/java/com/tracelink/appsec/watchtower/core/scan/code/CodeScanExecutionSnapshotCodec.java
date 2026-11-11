package com.tracelink.appsec.watchtower.core.scan.code;

import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Strict bounded snapshot persistence; a failed write must not silently discard provenance. */
public final class CodeScanExecutionSnapshotCodec {
	private static final int MAX_BYTES = 8 * 1024 * 1024;
	private static final ObjectMapper MAPPER = new ObjectMapper()
			.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
	private CodeScanExecutionSnapshotCodec() { }

	public static String encode(CodeScanExecutionSnapshot snapshot) {
		if (snapshot == null) return null;
		try {
			byte[] bytes = MAPPER.writeValueAsBytes(snapshot);
			if (bytes.length > MAX_BYTES) throw new IllegalArgumentException("Execution snapshot exceeds limit");
			return new String(bytes, StandardCharsets.UTF_8);
		} catch (JsonProcessingException e) {
			throw new IllegalArgumentException("Could not encode execution snapshot", e);
		}
	}

	public static CodeScanExecutionSnapshot decode(String json) {
		if (json == null || json.isBlank()) return null;
		if (json.length() > MAX_BYTES || json.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES)
			throw new IllegalArgumentException("Execution snapshot exceeds limit");
		try {
			return MAPPER.readValue(json, CodeScanExecutionSnapshot.class);
		} catch (JsonProcessingException e) {
			throw new IllegalArgumentException("Could not decode execution snapshot", e);
		}
	}
}
