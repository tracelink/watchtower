package com.tracelink.appsec.module.awssecurity;

import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;
import io.micrometer.core.instrument.MeterRegistry;

/** Restart-safe, low-cardinality operational gauges from typed JPA aggregate projections. */
@Component
public class AwsSecurityMetrics {
    private final AwsSecurityRunRepository runs;
    private final AwsSecurityCapacity capacity;
    private final ConcurrentHashMap<String, Double> values = new ConcurrentHashMap<>();
    private static final java.util.List<String> SEVERITIES = java.util.List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN");
    private static final java.util.List<String> VALIDATIONS = java.util.stream.Stream.concat(
        java.util.Arrays.stream(software.amazon.awssdk.services.securityagent.model.ValidationStatus.values()).filter(v -> !v.name().equals("UNKNOWN_TO_SDK_VERSION")).map(Object::toString), java.util.stream.Stream.of("UNKNOWN")).distinct().toList();
    @org.springframework.beans.factory.annotation.Autowired
    public AwsSecurityMetrics(AwsSecurityRunRepository runs, MeterRegistry meters, AwsSecurityCapacity capacity) {
        this.runs=runs; this.capacity=capacity;
        for (var stage : AwsSecurityRun.Stage.values()) {
            String key=stage.name(); values.put(key, 0d);
            meters.gauge("watchtower.aws.security.jobs", java.util.List.of(io.micrometer.core.instrument.Tag.of("stage", key)), values, m -> m.get(key));
        }
        for (String key : java.util.List.of("unresolved", "input.bytes", "imported", "missing", "omitted", "failures", "throttles", "capacity.used", "capacity.limit", "input.oldest.seconds", "latency.mean.seconds")) {
            values.put(key, 0d); meters.gauge("watchtower.aws.security." + key, values, m -> m.get(key));
        }
        // Metrics may be constructed before the module's Flyway migration creates the permit table.
        values.put("capacity.limit", (double) capacity.deploymentDefault());
        for (String label : SEVERITIES) register(meters, "severity", label);
        for (String label : VALIDATIONS) register(meters, "validation", label);
    }
    AwsSecurityMetrics(AwsSecurityRunRepository runs, MeterRegistry meters) {
        this(runs, meters, new AwsSecurityCapacity(1));
    }
    private void register(MeterRegistry meters, String dimension, String label) {
        String key = dimension + ":" + label; values.put(key, 0d);
        meters.gauge("watchtower.aws.security.findings." + dimension, java.util.List.of(io.micrometer.core.instrument.Tag.of(dimension, label)), values, m -> m.get(key));
    }
    private void evidence(String dimension, java.util.List<String> allowed, java.util.List<AwsSecurityRunRepository.EvidenceCount> counts) {
        for (String label : allowed) values.put(dimension + ":" + label, 0d);
        for (var count : counts) values.merge(dimension + ":" + (allowed.contains(count.getLabel()) ? count.getLabel() : "UNKNOWN"), (double)count.getFindings(), Double::sum);
    }
    @Scheduled(fixedDelayString="${watchtower.aws-security.metrics-ms:30000}")
    public void refresh() {
        var totals=runs.operationalTotals();
        for (var stage : AwsSecurityRun.Stage.values()) values.put(stage.name(), 0d);
        long bytes=0, imported=0, missing=0, omitted=0, failures=0, throttles=0;
        for (var total : totals) {
            values.put(total.getStage().name(), (double)total.getJobs());
            bytes+=total.getInputBytes(); imported+=total.getImported(); missing+=total.getMissing(); omitted+=total.getOmitted(); failures+=total.getFailures(); throttles+=total.getThrottles();
        }
        values.put("input.bytes", (double)bytes); values.put("imported", (double)imported); values.put("missing", (double)missing);
        values.put("omitted", (double)omitted); values.put("failures", (double)failures); values.put("throttles", (double)throttles);
        values.put("capacity.used", (double)runs.activePermitCount());
        values.put("capacity.limit", (double)capacity.limit());
        evidence("severity", SEVERITIES, runs.severityTotals()); evidence("validation", VALIDATIONS, runs.validationTotals());
        values.put("unresolved", (double)runs.countByNeedsReconciliationTrue());
        values.put("input.oldest.seconds", runs.oldestInput().map(t -> Math.max(0d, (System.currentTimeMillis()-t)/1000d)).orElse(0d));
        values.put("latency.mean.seconds", runs.averageLatencyMillis().orElse(0d)/1000d);
    }
}
