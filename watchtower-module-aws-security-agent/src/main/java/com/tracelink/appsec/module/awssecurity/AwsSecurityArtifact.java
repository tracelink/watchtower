package com.tracelink.appsec.module.awssecurity;

import java.util.List;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails;

/** Immutable manifest + bounded pages. Provider caps are separate from import completeness. */
public record AwsSecurityArtifact(int schema, String runId, AwsSecuritySnapshot snapshot, String providerStatus,
        String importStatus, int summaryPages, int returned, int imported, List<String> missingIds,
        List<String> omissions, Integer providerFindingCap, List<String> pages, InputReceipt input,
        java.util.Map<String, Integer> nativeSeverityCounts, java.util.Map<String, Integer> validationCounts, java.util.Set<String> sourceSuppressedFiles, int omittedFindings, AwsSecurityJobReceipt job) {
    public AwsSecurityArtifact(int schema, String runId, AwsSecuritySnapshot snapshot, String providerStatus, String importStatus, int summaryPages, int returned, int imported, List<String> missingIds, List<String> omissions, Integer providerFindingCap, List<String> pages, InputReceipt input, java.util.Map<String,Integer> severity, java.util.Map<String,Integer> validation) {
        this(schema, runId, snapshot, providerStatus, importStatus, summaryPages, returned, imported, missingIds, omissions, providerFindingCap, pages, input, severity, validation, java.util.Set.of(), 0, null);
    }
    public AwsSecurityArtifact { sourceSuppressedFiles = sourceSuppressedFiles == null ? java.util.Set.of() : java.util.Set.copyOf(sourceSuppressedFiles); }
    public record InputReceipt(String sourceSha256, long sourceBytes, int sourceFiles, String diffSha256,
            long diffBytes, List<String> exclusions, String comparison) { }
    public record Occurrence(String key, ProviderFindingDetails details, List<ProviderFindingDetails.Location> changedLineAnchors) {
        public Occurrence(String key, ProviderFindingDetails details) { this(key, details, List.of()); }
    }
}
