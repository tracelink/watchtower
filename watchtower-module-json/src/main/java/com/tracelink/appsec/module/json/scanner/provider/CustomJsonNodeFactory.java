package com.tracelink.appsec.module.json.scanner.provider;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.IdentityHashMap;
import java.util.Map;
import com.fasterxml.jackson.databind.node.*;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.BinaryNode;
import com.fasterxml.jackson.databind.node.BooleanNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.NumericNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.databind.node.ValueNode;
import com.fasterxml.jackson.databind.util.RawValue;

/**
 * Used to store references between nodes and JsonLocations. Otherwise, delegates to actual
 * JsonNodeFactory
 * 
 * @author csmith
 *
 */
public class CustomJsonNodeFactory extends JsonNodeFactory {

	private static final long serialVersionUID = 8807395553661461181L;

	private final JsonNodeFactory delegate;
	private final CustomParserFactory parserFactory;

	// Node equality is value-based; occurrences (including equal scalars) have distinct identity.
	private final Map<JsonNode, JsonLocation> locationMapping = new IdentityHashMap<>();

	public CustomJsonNodeFactory() { this(JsonNodeFactory.instance, null); }

	public CustomJsonNodeFactory(JsonNodeFactory nodeFactory,
			CustomParserFactory parserFactory) {
		delegate = nodeFactory;
		this.parserFactory = parserFactory;
	}

	/**
	 * Given a node, find its location, or null if it wasn't found
	 * 
	 * @param jsonNode the node to search for
	 * @return the location of the node or null if not found
	 */
	public JsonLocation getLocationForNode(JsonNode jsonNode) {
		return locationMapping.get(jsonNode);
	}

	/**
	 * Simple interceptor to mark the node in the lookup list and return it back
	 * 
	 * @param <T>  the type of the JsonNode
	 * @param node the node itself
	 * @return the node itself, having marked its location
	 */
	private <T extends JsonNode> T markNode(T node) {
		if (parserFactory != null) locationMapping.put(node, parserFactory.getParser().getTokenLocation());
		return node;
	}

	public <T extends JsonNode> T locate(T node, int line, int column) {
		locationMapping.put(node, new JsonLocation(null, -1, -1, line, column));
		return node;
	}
	private static final class OccurrenceBoolean extends BooleanNode { OccurrenceBoolean(boolean value) { super(value); } }
	private static final class OccurrenceNull extends NullNode { OccurrenceNull() { super(); } }

	@Override
	public BooleanNode booleanNode(boolean v) {
		return markNode(new OccurrenceBoolean(v));
	}

	@Override
	public NullNode nullNode() {
		return markNode(new OccurrenceNull());
	}

	@Override
	public NumericNode numberNode(byte v) {
		return markNode(new IntNode(v));
	}

	@Override
	public ValueNode numberNode(Byte value) {
		return value == null ? nullNode() : numberNode(value.byteValue());
	}

	@Override
	public NumericNode numberNode(short v) {
		return markNode(new ShortNode(v));
	}

	@Override
	public ValueNode numberNode(Short value) {
		return value == null ? nullNode() : numberNode(value.shortValue());
	}

	@Override
	public NumericNode numberNode(int v) {
		return markNode(new IntNode(v));
	}

	@Override
	public ValueNode numberNode(Integer value) {
		return value == null ? nullNode() : numberNode(value.intValue());
	}

	@Override
	public NumericNode numberNode(long v) {
		return markNode(new LongNode(v));
	}

	@Override
	public ValueNode numberNode(Long value) {
		return value == null ? nullNode() : numberNode(value.longValue());
	}

	@Override
	public ValueNode numberNode(BigInteger v) {
		return markNode(new BigIntegerNode(v));
	}

	@Override
	public NumericNode numberNode(float v) {
		return markNode(new FloatNode(v));
	}

	@Override
	public ValueNode numberNode(Float value) {
		return value == null ? nullNode() : numberNode(value.floatValue());
	}

	@Override
	public NumericNode numberNode(double v) {
		return markNode(new DoubleNode(v));
	}

	@Override
	public ValueNode numberNode(Double value) {
		return value == null ? nullNode() : numberNode(value.doubleValue());
	}

	@Override
	public ValueNode numberNode(BigDecimal v) {
		return markNode(new DecimalNode(v));
	}

	@Override
	public TextNode textNode(String text) {
		return markNode(new TextNode(text));
	}

	@Override
	public BinaryNode binaryNode(byte[] data) {
		return markNode(delegate.binaryNode(data));
	}

	@Override
	public BinaryNode binaryNode(byte[] data, int offset, int length) {
		return markNode(delegate.binaryNode(data, offset, length));
	}

	@Override
	public ValueNode pojoNode(Object pojo) {
		return markNode(delegate.pojoNode(pojo));
	}

	@Override
	public ValueNode rawValueNode(RawValue value) {
		return markNode(delegate.rawValueNode(value));
	}

	@Override
	public ArrayNode arrayNode() {
		return markNode(delegate.arrayNode());
	}

	@Override
	public ArrayNode arrayNode(int capacity) {
		return markNode(delegate.arrayNode(capacity));
	}

	@Override
	public ObjectNode objectNode() {
		return markNode(delegate.objectNode());
	}

}
