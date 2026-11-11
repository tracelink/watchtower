package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.securityagent.model.CodeReviewJob;

/** Provider progress without title, overview, documents, source, scripts or error prose. */
public record AwsSecurityJobReceipt(String providerStatus, String createdAt, String updatedAt,
        String errorCode, List<Step> steps, int returnedSteps, boolean stepsTruncated,
        String requestedValidation, String requestedRemediation, String engineVersion,
        String securityRequirementsRevision) {
    private static final ObjectMapper JSON = new ObjectMapper();
    public record Step(String name, String status, String createdAt, String updatedAt) { }
    static AwsSecurityJobReceipt of(CodeReviewJob job) {
        return new AwsSecurityJobReceipt(AwsSecurityFindingMapper.atom(job.statusAsString()), time(job.createdAt()), time(job.updatedAt()),
            job.errorInformation() == null ? null : AwsSecurityFindingMapper.atom(job.errorInformation().codeAsString()),
            job.steps().stream().limit(64).map(s -> new Step(AwsSecurityFindingMapper.atom(s.nameAsString()), AwsSecurityFindingMapper.atom(s.statusAsString()), time(s.createdAt()), time(s.updatedAt()))).toList(),
            job.steps().size(), job.steps().size() > 64, "DISABLED", "DISABLED", "UNKNOWN", "NOT_EXPOSED");
    }
    private static String time(java.time.Instant value) { return value == null ? null : value.toString(); }
    public String encode() {
        try { return JSON.writeValueAsString(this); } catch (java.io.IOException e) { throw new IllegalArgumentException("Invalid job receipt", e); }
    }
    static AwsSecurityJobReceipt decode(String json) {
        if (json == null) return null;
        if (json.length() > 32768) throw new IllegalArgumentException("Job receipt exceeds bound");
        try { return JSON.readValue(json, AwsSecurityJobReceipt.class); } catch (java.io.IOException e) { throw new IllegalArgumentException("Invalid job receipt", e); }
    }
}
