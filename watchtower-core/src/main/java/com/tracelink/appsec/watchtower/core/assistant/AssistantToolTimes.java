package com.tracelink.appsec.watchtower.core.assistant;

import java.time.Instant;
import java.util.Iterator;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Tool results store times as epoch milliseconds. A model asked to turn one into a date gets it
 * wrong (an answer in the Dev E2E run was 8 hours out), so every such time also carries the same
 * moment as an ISO-8601 UTC string, which the model can quote as it is.
 */
final class AssistantToolTimes {

	/** Numbers below this (about March 1973 in milliseconds) are counts or ids, not times. */
	private static final long MIN_EPOCH_MILLIS = 100_000_000_000L;

	private static final String UTC_SUFFIX = "_utc";

	private AssistantToolTimes() {
	}

	/**
	 * A copy of the tree in which each time-named number (a name ending in {@code _at} or
	 * {@code At}, or {@code since}) is followed by a {@code <name>_utc} string. The input is not
	 * changed.
	 */
	static JsonNode withUtc(JsonNode node) {
		if (node instanceof ObjectNode object) {
			ObjectNode copy = JsonNodeFactory.instance.objectNode();
			Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
			while (fields.hasNext()) {
				Map.Entry<String, JsonNode> field = fields.next();
				copy.set(field.getKey(), withUtc(field.getValue()));
				if (isEpochTime(field.getKey(), field.getValue())) {
					copy.put(field.getKey() + UTC_SUFFIX,
							Instant.ofEpochMilli(field.getValue().asLong()).toString());
				}
			}
			return copy;
		}
		if (node instanceof ArrayNode array) {
			ArrayNode copy = JsonNodeFactory.instance.arrayNode();
			array.forEach(element -> copy.add(withUtc(element)));
			return copy;
		}
		return node;
	}

	private static boolean isEpochTime(String name, JsonNode value) {
		boolean timeName = name.endsWith("_at") || name.endsWith("At") || "since".equals(name);
		return timeName && value.isIntegralNumber() && value.canConvertToLong()
				&& value.asLong() >= MIN_EPOCH_MILLIS;
	}
}
