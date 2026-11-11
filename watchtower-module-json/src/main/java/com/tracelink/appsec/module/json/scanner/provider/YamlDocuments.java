package com.tracelink.appsec.module.json.scanner.provider;

import java.io.Reader;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.events.*;
import org.yaml.snakeyaml.nodes.*;
import org.yaml.snakeyaml.resolver.Resolver;

/** Event-based conversion keeps each alias occurrence distinct and never constructs tagged objects. */
public final class YamlDocuments {
    public static final int MAX_INPUT_BYTES = 2 * 1024 * 1024;
    private static final int MAX_NODES = 100_000, MAX_DEPTH = 64, MAX_ALIASES = 50;
    private final CustomJsonNodeFactory factory;
    private final Map<String, JsonNode> anchors = new HashMap<>();
    private final Resolver resolver = new Resolver();
    private final Scalars scalars;
    private Iterator<Event> events;
    private Event pending;
    private int nodes, aliases;

    public YamlDocuments(CustomJsonNodeFactory factory) {
        this.factory = factory;
        LoaderOptions options = new LoaderOptions();
        options.setCodePointLimit(MAX_INPUT_BYTES);
        options.setNestingDepthLimit(MAX_DEPTH);
        options.setMaxAliasesForCollections(MAX_ALIASES);
        options.setAllowDuplicateKeys(false);
        scalars = new Scalars(options);
    }

    public List<JsonNode> read(Reader reader) {
        LoaderOptions options = new LoaderOptions();
        options.setCodePointLimit(MAX_INPUT_BYTES);
        events = new Yaml(options).parse(reader).iterator();
        List<JsonNode> documents = new ArrayList<>();
        expect(Event.ID.StreamStart);
        while (!peek().is(Event.ID.StreamEnd)) {
            if (documents.size() >= 100) throw invalid();
            expect(Event.ID.DocumentStart);
            anchors.clear();
            documents.add(node(0));
            expect(Event.ID.DocumentEnd);
        }
        expect(Event.ID.StreamEnd);
        return documents;
    }

    private JsonNode node(int depth) {
        count(depth);
        Event event = take();
        if (event instanceof AliasEvent alias) {
            if (++aliases > MAX_ALIASES || !anchors.containsKey(alias.getAnchor())) throw invalid();
            return copy(anchors.get(alias.getAnchor()), event, depth);
        }
        JsonNode result;
        if (event instanceof ScalarEvent scalar) {
            Tag tag = scalar.getTag() == null || scalar.getTag().equals("!")
                    ? resolver.resolve(NodeId.scalar, scalar.getValue(), scalar.isPlain()) : new Tag(scalar.getTag());
            if (tag.equals(Tag.STR) || tag.equals(Tag.TIMESTAMP) || tag.equals(Tag.MERGE)) {
                result = factory.textNode(scalar.getValue());
            } else if (tag.equals(Tag.NULL)) {
                result = factory.nullNode();
            } else if (Set.of(Tag.BOOL, Tag.INT, Tag.FLOAT).contains(tag)) {
                Object value = scalars.value(new ScalarNode(tag, scalar.getValue(), scalar.getStartMark(), scalar.getEndMark(), scalar.getScalarStyle()));
                if (value instanceof Boolean b) result = factory.booleanNode(b);
                else if (value instanceof Number n) {
                    if (n instanceof Double d && !Double.isFinite(d)) throw invalid();
                    result = n instanceof java.math.BigInteger b ? factory.numberNode(b)
                            : n instanceof Double d ? factory.numberNode(d) : factory.numberNode(n.longValue());
                } else throw invalid();
            } else throw invalid();
        } else if (event instanceof SequenceStartEvent sequence) {
            tag(sequence, Tag.SEQ);
            ArrayNode array = factory.arrayNode();
            while (!peek().is(Event.ID.SequenceEnd)) array.add(node(depth + 1));
            take();
            result = array;
        } else if (event instanceof MappingStartEvent mapping) {
            tag(mapping, Tag.MAP);
            ObjectNode explicit = factory.objectNode(), merged = factory.objectNode();
            Set<String> keys = new HashSet<>();
            while (!peek().is(Event.ID.MappingEnd)) {
                Event keyEvent = peek();
                if (!(keyEvent instanceof ScalarEvent key)) throw invalid();
                node(depth + 1); // validate tags and count even keys; keys are textual in JSONPath.
                String name = key.getValue();
                if (!keys.add(name)) throw invalid();
                JsonNode value = node(depth + 1);
                if (name.equals("<<") && (key.getTag() == null && key.isPlain() || Tag.MERGE.getValue().equals(key.getTag()))) merge(merged, value);
                else explicit.set(name, value);
            }
            take();
            merged.setAll(explicit); // explicit keys override merges regardless of ordering.
            result = merged;
        } else throw invalid();
        factory.locate(result, event.getStartMark().getLine() + 1, event.getStartMark().getColumn() + 1);
        if (event instanceof NodeEvent n && n.getAnchor() != null) {
            if (anchors.putIfAbsent(n.getAnchor(), result) != null) throw invalid();
        }
        return result;
    }

    private void merge(ObjectNode destination, JsonNode value) {
        if (value.isArray()) { for (JsonNode item : value) merge(destination, item); }
        else if (value.isObject()) value.fields().forEachRemaining(e -> { if (!destination.has(e.getKey())) destination.set(e.getKey(), e.getValue()); });
        else throw invalid();
    }

    private JsonNode copy(JsonNode source, Event alias, int depth) {
        count(depth);
        JsonNode result;
        if (source.isObject()) {
            ObjectNode object = factory.objectNode();
            source.fields().forEachRemaining(e -> object.set(e.getKey(), copy(e.getValue(), alias, depth + 1)));
            result = object;
        } else if (source.isArray()) {
            ArrayNode array = factory.arrayNode();
            source.forEach(e -> array.add(copy(e, alias, depth + 1)));
            result = array;
        } else if (source.isNull()) result = factory.nullNode();
        else if (source.isBoolean()) result = factory.booleanNode(source.booleanValue());
        else if (source.isBigInteger()) result = factory.numberNode(source.bigIntegerValue());
        else if (source.isIntegralNumber()) result = factory.numberNode(source.longValue());
        else if (source.isNumber()) result = factory.numberNode(source.doubleValue());
        else result = factory.textNode(source.textValue());
        return factory.locate(result, alias.getStartMark().getLine() + 1, alias.getStartMark().getColumn() + 1);
    }
    private void count(int depth) { if (++nodes > MAX_NODES || depth > MAX_DEPTH) throw invalid(); }
    private void tag(CollectionStartEvent event, Tag expected) { if (event.getTag() != null && !event.getTag().equals("!") && !event.getTag().equals(expected.getValue())) throw invalid(); }
    private Event peek() { if (pending == null) { if (!events.hasNext()) throw invalid(); pending = events.next(); } return pending; }
    private Event take() { Event event = peek(); pending = null; return event; }
    private void expect(Event.ID id) { if (!take().is(id)) throw invalid(); }
    private IllegalArgumentException invalid() { return new IllegalArgumentException("Unsupported or excessive YAML structure"); }
    private static final class Scalars extends SafeConstructor {
        Scalars(LoaderOptions options) { super(options); }
        Object value(ScalarNode node) { return constructObject(node); }
    }
}
