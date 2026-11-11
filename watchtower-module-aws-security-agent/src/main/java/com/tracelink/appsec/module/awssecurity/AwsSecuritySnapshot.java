package com.tracelink.appsec.module.awssecurity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.scan.code.ScanExecutionContext;

/** Frozen execution policy; settings edits cannot silently rebind an in-flight assessment. */
public record AwsSecuritySnapshot(ScanExecutionContext context, AwsSecuritySettings.Profile profile,
        RuleExecutionIdentity rule, String ruleName, RulePriority blockingLevel, String policyRevision) {
    private static final ObjectMapper JSON = new ObjectMapper();
    public String encode() {
        try { return JSON.writeValueAsString(this); } catch (Exception e) { throw new IllegalStateException("Cannot encode AWS execution"); }
    }
    public static AwsSecuritySnapshot decode(String json) {
        try { return JSON.readValue(json, AwsSecuritySnapshot.class); } catch (Exception e) { throw new IllegalStateException("Cannot decode AWS execution"); }
    }
}
