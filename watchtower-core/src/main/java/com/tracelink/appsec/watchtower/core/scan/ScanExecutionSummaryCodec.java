package com.tracelink.appsec.watchtower.core.scan;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution;
import java.util.Collections;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Safe JSON persistence for scanner execution details. */
public final class ScanExecutionSummaryCodec {
	private static final Logger LOG = LoggerFactory.getLogger(ScanExecutionSummaryCodec.class);
	private static final ObjectMapper MAPPER = new ObjectMapper();
	private static final TypeReference<List<ScannerExecution>> TYPE = new TypeReference<>() { };

	private ScanExecutionSummaryCodec() { }

	public static String encode(List<ScannerExecution> scanners) {
		try {
			return MAPPER.writeValueAsString(scanners == null ? Collections.emptyList() : scanners);
		} catch (JsonProcessingException e) {
			LOG.warn("Could not serialize scan execution details", e);
			return "[]";
		}
	}

	public static List<ScannerExecution> decode(String json) {
		if (json == null || json.isBlank()) return Collections.emptyList();
		try {
			return List.copyOf(MAPPER.readValue(json, TYPE));
		} catch (JsonProcessingException | RuntimeException e) {
			LOG.warn("Could not read scan execution details", e);
			return Collections.emptyList();
		}
	}
}
