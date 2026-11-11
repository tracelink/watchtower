package com.tracelink.appsec.watchtower.core.scan.code.report;

import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService;
import com.tracelink.appsec.watchtower.core.scan.code.ScanExecutionContext;

/** Small common report linkage. Evidence stays in immutable, independently bounded provider pages. */
public record ProviderAssessmentReference(String provider, String runId, String artifactKey,
        RemoteAssessmentService.Status status, ScanExecutionContext context, RuleExecutionIdentity policy,
        String policyName, String policyRevision, Map<String, Integer> validationCounts, int omittedFindings) {
    private static final ObjectMapper JSON = new ObjectMapper();
    public ProviderAssessmentReference { validationCounts = validationCounts == null ? Map.of() : Map.copyOf(validationCounts); }
    public static String encode(List<ProviderAssessmentReference> references) {
        try { String json = JSON.writeValueAsString(references); if (json.length() > 65536) throw new IllegalArgumentException("Provider summary exceeds bound"); return json; }
        catch (java.io.IOException e) { throw new IllegalArgumentException("Provider summary unavailable", e); }
    }
    public static List<ProviderAssessmentReference> decode(String json) {
        if (json == null || json.isBlank()) return List.of();
        if (json.length() > 65536) throw new IllegalArgumentException("Provider summary exceeds bound");
        try { return List.of(JSON.readValue(json, ProviderAssessmentReference[].class)); }
        catch (java.io.IOException e) { throw new IllegalArgumentException("Provider summary unavailable", e); }
    }
}
