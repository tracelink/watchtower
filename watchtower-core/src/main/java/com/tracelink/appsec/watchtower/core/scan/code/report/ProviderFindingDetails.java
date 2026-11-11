package com.tracelink.appsec.watchtower.core.scan.code.report;

import java.util.List;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/** Source-free provider evidence; confidence and validation deliberately have separate fields. */
public record ProviderFindingDetails(String provider, String account, String region, String spaceId,
        String reviewId, String jobId, String findingId, String taskId, String mapperVersion,
        String title, String description, String riskType, String nativeSeverity, String riskScore,
        String reasoning, String confidence, String validationStatus, String workflowStatus,
        List<Location> locations, List<String> omissions, boolean sensitive, String providerUrl, List<Integer> sourceLocations, String sensitivityReason, String createdAt, String updatedAt) {
    public ProviderFindingDetails(String provider, String account, String region, String spaceId, String reviewId, String jobId, String findingId, String taskId, String mapperVersion, String title, String description, String riskType, String nativeSeverity, String riskScore, String reasoning, String confidence, String validationStatus, String workflowStatus, List<Location> locations, List<String> omissions, boolean sensitive) {
        this(provider, account, region, spaceId, reviewId, jobId, findingId, taskId, mapperVersion, title, description, riskType, nativeSeverity, riskScore, reasoning, confidence, validationStatus, workflowStatus, locations, omissions, sensitive, null, List.of(), "Legacy evidence: source suppressed", null, null);
    }
    public ProviderFindingDetails {
        sourceLocations = sourceLocations == null ? List.of() : List.copyOf(sourceLocations);
        locations = locations == null ? List.of() : List.copyOf(locations);
        omissions = omissions == null ? List.of() : List.copyOf(omissions);
    }
    public record Location(String file, int startLine, int endLine, String label) {
        public static boolean valid(String file, Integer start, Integer end) {
            if (file == null || file.isBlank() || file.length() > 1024 || file.startsWith("/")
                    || file.contains("\\") || file.contains(":") || file.contains("?") || file.contains("#") || file.contains("%") || file.chars().anyMatch(Character::isISOControl)
                    || start == null || end == null || start < 1 || end < start) return false;
            return java.util.Arrays.stream(file.split("/", -1)).noneMatch(s -> s.isEmpty() || s.equals(".") || s.equals(".."));
        }
    }
    /**
     * The same finding with the given locations as the only ones whose code may be shown, so a chip is never offered for a location
     * the source endpoint would refuse. When none is left the reason says why.
     */
    public ProviderFindingDetails withSourceLocations(List<Integer> allowed, String reason) {
        return new ProviderFindingDetails(provider, account, region, spaceId, reviewId, jobId, findingId, taskId, mapperVersion,
            title, description, riskType, nativeSeverity, riskScore, reasoning, confidence, validationStatus, workflowStatus,
            locations, omissions, allowed.isEmpty() || sensitive, providerUrl, allowed,
            allowed.isEmpty() ? reason : sensitivityReason, createdAt, updatedAt);
    }
    public RulePriority legacyPriority() {
        return switch (nativeSeverity == null ? "" : nativeSeverity) {
            case "CRITICAL", "HIGH" -> RulePriority.HIGH;
            case "MEDIUM" -> RulePriority.MEDIUM;
            case "LOW" -> RulePriority.LOW;
            case "INFORMATIONAL" -> RulePriority.INFORMATIONAL;
            default -> null;
        };
    }
    public String severity() {
        return switch (nativeSeverity == null ? "" : nativeSeverity) {
            case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL" -> nativeSeverity;
            default -> "UNKNOWN";
        };
    }
}
