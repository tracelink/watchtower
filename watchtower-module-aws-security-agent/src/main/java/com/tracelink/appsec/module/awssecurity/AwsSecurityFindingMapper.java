package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import software.amazon.awssdk.services.securityagent.model.Finding;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location;

/** Conservative source-free policy. Arbitrary provider prose cannot be proved source-free by regex. */
public final class AwsSecurityFindingMapper {
    public static final String VERSION = "4-pinned-source-policy";
    public ProviderFindingDetails map(Finding f, AwsSecuritySnapshot s, String review, String job) {
        return map(f, s, review, job, null);
    }
    public ProviderFindingDetails map(Finding f, AwsSecuritySnapshot s, String review, String job, AwsSecuritySourceIndex source) {
        if (!Objects.equals(s.profile().spaceId(), f.agentSpaceId()) || !Objects.equals(review, f.codeReviewId())
                || !Objects.equals(job, f.codeReviewJobId())) throw new IllegalArgumentException("Finding association mismatch");
        List<String> omissions = new ArrayList<>(); List<Location> locations = new ArrayList<>();
        for (var location : f.codeLocations()) {
            String path = source == null ? location.filePath() : source.exportedPath(location.filePath()).orElse(null);
            if (Location.valid(path, location.lineStart(), location.lineEnd()))
                locations.add(new Location(path, location.lineStart(), location.lineEnd(), null));
            else omissions.add("Location did not match an exported file or valid line range");
        }
        omissions.add("Provider narrative and source are fetched on demand; they are not retained in this report");
        omissions.add("SDK 2.46.21 does not expose remediationCode or originalFindingId");
        if (f.codeLocations().isEmpty()) omissions.add("Code locations not provided");
        locations = locations.stream().distinct().sorted(Comparator.comparing(Location::file).thenComparingInt(Location::startLine).thenComparingInt(Location::endLine)).toList();
        List<Integer> allowed = new ArrayList<>();
        boolean qualified = source != null && Objects.equals(source.commit(), s.context().commit())
            && source.permits(f.riskType()) && !AwsSecurityEvidencePolicy.secretNamed(f.name());
        if (qualified) for (int i = 0; i < locations.size(); i++) {
            var location = locations.get(i);
            if (!AwsSecurityInputStore.excluded(location.file()) && source.file(location.file()).isPresent()) allowed.add(i);
        }
        String riskType = qualified ? f.riskType() : atom(f.riskType());
        String sensitivity = secretFinding(f) ? SECRET_REASON
            : source != null && !source.permits(f.riskType()) ? SOURCE_OFF_REASON
            : !qualified || allowed.isEmpty() ? UNAVAILABLE_REASON
            : "Source is fetched from the scanned commit and checked against the uploaded file hash";
        return new ProviderFindingDetails("AWS_SECURITY_AGENT", s.profile().account(), s.profile().region(), s.profile().spaceId(),
            review, job, atom(f.findingId()), atom(f.taskId()), VERSION, riskType == null ? "AWS security finding" : "AWS security finding: " + riskType, null, riskType,
            atom(f.riskLevelAsString()), score(f.riskScore()), null, atom(f.confidenceAsString()), atom(f.validationStatusAsString()),
            atom(f.statusAsString()), locations, omissions, allowed.isEmpty(), source == null ? AwsSecurityEvidencePolicy.AWS_LOGIN_GUIDE : Objects.requireNonNullElse(AwsSecurityEvidencePolicy.reviewUrl(source.webAppUrl(),s.profile().spaceId(),review),AwsSecurityEvidencePolicy.AWS_LOGIN_GUIDE), allowed, sensitivity, f.createdAt() == null ? null : f.createdAt().toString(), f.updatedAt() == null ? null : f.updatedAt().toString());
    }
    static final String SECRET_REASON = "Secret and credential findings never show code.";
    static final String SOURCE_OFF_REASON = "Source is off for AWS findings. An admin can turn on Show source in AWS Security Agent settings.";
    static final String UNAVAILABLE_REASON = "Code can’t be shown for this location.";
    private static boolean secretFinding(Finding f) {
        return AwsSecurityEvidencePolicy.secretFinding(f.riskType(), f.name());
    }
    static String atom(String value) { return value != null && value.matches("[A-Za-z0-9_.:/-]{1,128}") ? value : null; }
    static String score(String value) { return value != null && value.matches("[0-9]{1,4}(\\.[0-9]{1,4})?") ? value : null; }
}
