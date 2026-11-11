package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

class AssistantToolTimesTest {

	private static final ObjectMapper MAPPER = new ObjectMapper();

	private static JsonNode json(String text) throws Exception {
		return MAPPER.readTree(text);
	}

	@Test
	void anEpochTimeGetsAnIsoUtcSiblingSoTheModelDoesNotConvertIt() throws Exception {
		// Dev E2E A07: an answer said the evidence was computed 8 hours later than it was.
		JsonNode in = json("{\"computed_at\":1793640000000,\"data\":{\"since\":1793553600000,\"rule_id\":1718}}");

		JsonNode out = AssistantToolTimes.withUtc(in);

		assertEquals("2026-11-02T17:20:00Z", out.path("computed_at_utc").asText());
		assertEquals(1793640000000L, out.path("computed_at").asLong());
		assertEquals("2026-11-01T17:20:00Z", out.path("data").path("since_utc").asText());
		assertFalse(out.path("data").has("rule_id_utc"), "an id is not a time");
	}

	@Test
	void timesInsideListsAndCamelCaseNamesAreConvertedToo() throws Exception {
		JsonNode out = AssistantToolTimes.withUtc(json("{\"rows\":[{\"createdAt\":1793640000000},{\"count\":5}]}"));

		assertEquals("2026-11-02T17:20:00Z", out.path("rows").path(0).path("createdAt_utc").asText());
		assertFalse(out.path("rows").path(1).has("count_utc"));
	}

	@Test
	void smallNumbersAndTextAreLeftAlone() throws Exception {
		JsonNode in = json("{\"found_at\":3,\"note_at\":\"yesterday\",\"merged_at\":null}");

		JsonNode out = AssistantToolTimes.withUtc(in);

		assertEquals(in, out);
		assertNotSame(in, out, "the input tree is never changed");
	}
}
