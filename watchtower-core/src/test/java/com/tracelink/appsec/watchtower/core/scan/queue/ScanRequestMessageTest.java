package com.tracelink.appsec.watchtower.core.scan.queue;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * IMPROVEMENT_PLAN.md item 4.2's test requirement: JSON round-trip with all fields
 * populated, including special characters and a large prId value.
 */
public class ScanRequestMessageTest {

	private final ObjectMapper objectMapper = new ObjectMapper();

	@Test
	public void testJsonRoundTrip() throws Exception {
		ScanRequestMessage message =
				new ScanRequestMessage("api-label", "my-repo", "42", "abc123def456", 1700000000000L);

		String json = objectMapper.writeValueAsString(message);
		ScanRequestMessage roundTripped = objectMapper.readValue(json, ScanRequestMessage.class);

		assertEquals(message, roundTripped);
	}

	@Test
	public void testJsonRoundTripWithSpecialCharactersAndLargePrId() throws Exception {
		ScanRequestMessage message = new ScanRequestMessage("api/label", "repo with spaces & \"quotes\"",
				String.valueOf(Long.MAX_VALUE), "commit/with/slashes", Long.MAX_VALUE);

		String json = objectMapper.writeValueAsString(message);
		ScanRequestMessage roundTripped = objectMapper.readValue(json, ScanRequestMessage.class);

		assertEquals(message, roundTripped);
	}
}
