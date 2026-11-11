package com.tracelink.appsec.module.awssecurity;

import java.util.*;

/** Source-free proof of the exact exported ZIP root and per-file bytes. */
public record AwsSecuritySourceIndex(String commit, String archiveSha256, List<File> files,
        Set<String> approvedRiskTypes, String webAppUrl) {
    public record File(String path, String sha256, long bytes) { }
    public AwsSecuritySourceIndex {
        files = List.copyOf(files); approvedRiskTypes = Set.copyOf(approvedRiskTypes);
    }
    public Optional<File> file(String path) { return files.stream().filter(f -> f.path().equals(path)).findFirst(); }
    private static final java.util.regex.Pattern EXTRACTED = java.util.regex.Pattern.compile(
        "^(?:/tmp/opt/source_code/)?code_sc-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/(.+)$");
    /**
     * AWS reports paths below its extraction directory, not paths relative to the uploaded ZIP: absolute
     * ({@code /tmp/opt/source_code/code_sc-<id>/src/A.java}) or, as of later reviews, relative to the directory's parent
     * ({@code code_sc-<id>/src/A.java}). A path that is already relative to the ZIP is used as it is.
     */
    Optional<String> exportedPath(String providerPath) {
        if (providerPath == null) return Optional.empty();
        String relative = providerPath;
        var extracted = EXTRACTED.matcher(providerPath);
        if (extracted.matches()) relative = extracted.group(1);
        else if (providerPath.startsWith("/")) return Optional.empty();
        if (!com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location.valid(relative, 1, 1)
                || AwsSecurityInputStore.excluded(relative)) return Optional.empty();
        return file(relative).map(File::path);
    }
    boolean permits(String riskType) {
        return riskType != null && !AwsSecurityEvidencePolicy.secretType(riskType) && approvedRiskTypes.contains(riskType);
    }
}
