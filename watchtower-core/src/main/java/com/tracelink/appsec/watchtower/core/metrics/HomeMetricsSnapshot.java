package com.tracelink.appsec.watchtower.core.metrics;

/** Aggregated completed-scan projection values for the home overview. */
public record HomeMetricsSnapshot(long completed, long findings, double averageDurationMillis) { }
