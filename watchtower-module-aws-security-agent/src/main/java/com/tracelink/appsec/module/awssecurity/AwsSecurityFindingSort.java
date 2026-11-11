package com.tracelink.appsec.module.awssecurity;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.module.awssecurity.AwsSecurityArtifact.Occurrence;

/** External merge sort: bounded source-free scratch space, 100-record chunks and 16-way merges. */
final class AwsSecurityFindingSort implements AutoCloseable {
    static class LimitExceeded extends IOException {
        final String bound;
        LimitExceeded(String bound) { super("Evidence bound exceeded: " + bound); this.bound = bound; }
    }
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int FAN_IN = 16, MAX_RECORD = 128 * 1024;
    private static final long MAX_BYTES = 256L * 1024 * 1024;
    static final Comparator<Occurrence> ORDER = Comparator
        .comparingInt((Occurrence o) -> rank(o.details().severity(), List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")))
        .thenComparingInt(o -> rank(o.details().confidence(), List.of("HIGH", "MEDIUM", "LOW")))
        .thenComparing(o -> o.details().locations().isEmpty() ? "" : o.details().locations().getFirst().file())
        .thenComparingInt(o -> o.details().locations().isEmpty() ? 0 : o.details().locations().getFirst().startLine())
        .thenComparing(Occurrence::key);
    private static int rank(String value, List<String> values) { int i = value == null ? -1 : values.indexOf(value); return i < 0 ? values.size() : i; }
    private final Path directory = Files.createTempDirectory("aws-evidence-sort-");
    private final List<Path> chunks = new ArrayList<>();
    private final List<Occurrence> buffer = new ArrayList<>();
    private long bytes;
    AwsSecurityFindingSort() throws IOException { }
    void add(Occurrence occurrence) throws IOException {
        int size = JSON.writeValueAsBytes(occurrence).length;
        if (size > MAX_RECORD) throw new LimitExceeded("RECORD_BYTES");
        if ((bytes += size) > MAX_BYTES) throw new LimitExceeded("EVIDENCE_BYTES");
        buffer.add(occurrence);
        if (buffer.size() == 100) flush();
    }
    private void flush() throws IOException {
        if (buffer.isEmpty()) return;
        buffer.sort(ORDER);
        Path chunk = Files.createTempFile(directory, "chunk-", ".bin");
        try (var output = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(chunk)))) {
            for (var occurrence : buffer) write(output, occurrence);
        }
        chunks.add(chunk); buffer.clear();
    }
    interface Consumer { void accept(Occurrence occurrence) throws IOException; }
    void drain(Consumer consumer, Runnable ownership) throws IOException {
        flush();
        while (chunks.size() > FAN_IN) {
            List<Path> next = new ArrayList<>();
            for (int i = 0; i < chunks.size(); i += FAN_IN) {
                ownership.run();
                List<Path> inputs = chunks.subList(i, Math.min(chunks.size(), i + FAN_IN));
                Path output = Files.createTempFile(directory, "merge-", ".bin");
                try (var stream = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(output)))) {
                    merge(inputs, o -> write(stream, o));
                }
                for (Path input : inputs) Files.delete(input);
                next.add(output);
            }
            chunks.clear(); chunks.addAll(next);
        }
        merge(chunks, consumer);
    }
    private static void write(DataOutputStream output, Occurrence occurrence) throws IOException {
        byte[] data = JSON.writeValueAsBytes(occurrence); output.writeInt(data.length); output.write(data);
    }
    private static Occurrence read(DataInputStream input) throws IOException {
        int size;
        try { size = input.readInt(); } catch (EOFException done) { return null; }
        if (size < 1 || size > MAX_RECORD) throw new IOException("Invalid sort record");
        byte[] bytes = input.readNBytes(size);
        if (bytes.length != size) throw new EOFException("Truncated sort record");
        return JSON.readValue(bytes, Occurrence.class);
    }
    private static void merge(List<Path> paths, Consumer consumer) throws IOException {
        record Head(Occurrence occurrence, DataInputStream stream) { }
        List<DataInputStream> streams = new ArrayList<>();
        PriorityQueue<Head> heads = new PriorityQueue<>(Comparator.comparing(Head::occurrence, ORDER));
        try {
            for (Path path : paths) {
                var stream = new DataInputStream(new BufferedInputStream(Files.newInputStream(path))); streams.add(stream);
                var first = read(stream); if (first != null) heads.add(new Head(first, stream));
            }
            while (!heads.isEmpty()) {
                Head head = heads.remove(); consumer.accept(head.occurrence());
                var next = read(head.stream()); if (next != null) heads.add(new Head(next, head.stream()));
            }
        } finally { for (var stream : streams) stream.close(); }
    }
    public void close() throws IOException {
        try (var files = Files.list(directory)) { for (Path path : files.toList()) Files.deleteIfExists(path); }
        Files.deleteIfExists(directory);
    }
}
