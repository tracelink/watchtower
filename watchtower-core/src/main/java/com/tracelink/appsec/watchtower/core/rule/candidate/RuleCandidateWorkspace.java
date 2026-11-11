package com.tracelink.appsec.watchtower.core.rule.candidate;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** HTTP values are ordinary JSON types; canonical definition trees stay inside the service. */
public record RuleCandidateWorkspace(long ruleId, String revision, Map<String, Object> definition,
        Set<String> editableFields, Map<String, Field> fieldMetadata, boolean authoringAvailable,
        List<String> authoringReasons, boolean testingAvailable, List<Map<String, Object>> candidates,
        List<Map<String, Object>> fixtures, List<Map<String, Object>> history) {
    public record Field(String type, boolean nullable) { }
    public record DraftRequest(long ruleId, String baseRevision, Map<String, Object> changes,
            String rationale, String reviewId) { }
}
