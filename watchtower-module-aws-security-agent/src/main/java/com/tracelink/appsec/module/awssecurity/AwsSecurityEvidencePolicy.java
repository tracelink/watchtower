package com.tracelink.appsec.module.awssecurity;

import java.net.URI;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;

/** Reviewed risk types are frozen before upload; current policy also gates legacy source reads. */
@Component
public class AwsSecurityEvidencePolicy {
    static final String AWS_LOGIN_GUIDE = "https://docs.aws.amazon.com/securityagent/latest/userguide/login-web-app.html";
    /**
     * Every risk type AWS code reviews can return, except secret-like ones, plus the names earlier versions listed. Turning
     * "Show source" on allows all of them: secret and credential types are never options, so they stay masked.
     */
    private static final List<String> SOURCE_OPTIONS = sourceOptions();
    private static List<String> sourceOptions() {
        var types = new TreeSet<>(List.of("BUSINESS_LOGIC_VULNERABILITIES", "UNRESTRICTED_RESOURCE_CONSUMPTION",
            "DENIAL_OF_SERVICE", "INSECURE_DIRECT_OBJECT_REFERENCE", "DATABASE_MODIFICATION", "SERVER_ERROR_500",
            "SECURITY_MISCONFIGURATION", "SQL_INJECTION", "CROSS_SITE_SCRIPTING", "AUTHENTICATION_BYPASS",
            "BROKEN_OBJECT_PROPERTY_AUTHORIZATION", "PRIVILEGE_ESCALATION"));
        for (var type : software.amazon.awssdk.services.securityagent.model.RiskType.knownValues()) types.add(type.toString());
        types.removeIf(AwsSecurityEvidencePolicy::secretType);
        return List.copyOf(types);
    }
    private final Set<String> deploymentSourceRiskTypes;
    private final String webAppUrl;
    @Autowired(required = false) private AwsSecurityPermitRepository permits;
    @Autowired(required = false) private AwsSecurityAuditRepository audit;

    public AwsSecurityEvidencePolicy(@Value("${watchtower.aws-security.source-risk-types:BUSINESS_LOGIC_VULNERABILITIES,UNRESTRICTED_RESOURCE_CONSUMPTION,DENIAL_OF_SERVICE,INSECURE_DIRECT_OBJECT_REFERENCE,DATABASE_MODIFICATION,SERVER_ERROR_500,SECURITY_MISCONFIGURATION}") String types,
            @Value("${watchtower.aws-security.web-app-url:}") String url) {
        deploymentSourceRiskTypes = parse(types);
        webAppUrl = validatedUrl(url);
    }

    private static Set<String> parse(String types) {
        var approved = new TreeSet<String>();
        for (String type : types.split(",")) {
            type = type.trim();
            if (type.isEmpty()) continue;
            if (!type.matches("[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}") || secretType(type))
                throw new IllegalArgumentException("Unsafe AWS source risk type qualification");
            approved.add(type);
        }
        return Set.copyOf(approved);
    }

    /**
     * Whether a finding's own title says it is about a secret. Narrower than {@link #secretType}: "sensitive" and "unknown" appear in
     * the titles of ordinary findings (an IDOR that exposes sensitive data) and treating those as secrets hid the code of most
     * findings. Words that name a credential stay: a finding about a hardcoded token or webhook URL must never show its lines, because
     * only a local secrets scan can mask them and a pull request scan may not have run one.
     */
    static boolean secretNamed(String name) {
        if (name == null) return false;
        String normalized = name.replaceAll("[^A-Za-z]", "").toLowerCase(Locale.ROOT);
        return List.of("secret", "credential", "password", "privatekey", "apikey", "accesskey", "token", "webhook", "hardcoded")
            .stream().anyMatch(normalized::contains);
    }

    /** A finding whose risk type or title marks it as a secret: its code is never shown and its file stays hidden. */
    static boolean secretFinding(String riskType, String name) {
        return secretType(riskType) || secretNamed(name);
    }

    static boolean secretType(String type) {
        if (type == null) return false;
        String normalized = type.replaceAll("[^A-Za-z]", "").toLowerCase(Locale.ROOT);
        return List.of("secret", "credential", "password", "privatekey", "apikey", "token", "sensitive", "unknown")
            .stream().anyMatch(normalized::contains);
    }

    static String validatedUrl(String value) {
        if (value == null || value.isBlank() || AWS_LOGIN_GUIDE.equals(value)) return AWS_LOGIN_GUIDE;
        try {
            URI uri = URI.create(value);
            // Operator-supplied web-app domain, never a provider-returned link, auth token or deep-link guess.
            if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getPort() != -1 || uri.getRawQuery() != null || uri.getRawFragment() != null
                    || !(uri.getRawPath().isEmpty() || uri.getRawPath().equals("/"))
                    || !uri.getHost().matches("[a-z0-9][a-z0-9.-]*\\.[a-z]{2,}")) throw new IllegalArgumentException();
            return uri.toASCIIString();
        } catch (IllegalArgumentException e) { throw new IllegalArgumentException("AWS web-app URL must be an HTTPS domain without credentials, query or path"); }
    }
    /** Review route supplied and verified by the installation owner. IDs come from bound receipts. */
    static String reviewUrl(String origin,String space,String review) {
        String base=validatedUrl(origin);
        if(AWS_LOGIN_GUIDE.equals(base)||space==null||review==null||!space.matches("[A-Za-z0-9_-]{1,128}")||!review.matches("[A-Za-z0-9_-]{1,128}"))return null;
        return base.replaceAll("/+$","")+"/"+space+"/code-reviews/"+review;
    }
    String reviewUrl(AwsSecurityRun run) {return reviewUrl(webAppUrl,AwsSecuritySnapshot.decode(run.snapshotJson).profile().spaceId(),run.reviewId);}
    public record SourcePolicy(Set<String> riskTypes, Set<String> deploymentDefault, boolean overridden, List<String> options) {
        /** The setup page's one switch: on while any non-secret risk type may show source. */
        public boolean shown() { return !riskTypes.isEmpty(); }
    }
    /** Show source for AWS findings (UI switch). Secret and credential types are never options, so stay masked. */
    public boolean sourceShown() { return sourcePolicy().shown(); }
    public SourcePolicy sourcePolicy() {
        if (permits == null) return new SourcePolicy(shownTypes(deploymentSourceRiskTypes), deploymentSourceRiskTypes, false, SOURCE_OPTIONS);
        var row = permits.findById(1).orElseThrow(() -> new IllegalStateException("AWS permit control row is missing"));
        var current = row.sourceRiskTypes == null ? deploymentSourceRiskTypes : parse(row.sourceRiskTypes);
        // One switch (AWS setup board): on means every non-secret risk type, whatever list was saved or
        // configured before; the configured default only decides whether it starts on.
        return new SourcePolicy(shownTypes(current), deploymentSourceRiskTypes,
            row.sourceRiskTypes != null, SOURCE_OPTIONS);
    }
    Set<String> sourceRiskTypes() { return sourcePolicy().riskTypes(); }
    private static Set<String> shownTypes(Set<String> saved) { return saved.isEmpty() ? Set.of() : Set.copyOf(SOURCE_OPTIONS); }
    @Transactional
    public void saveSourceRiskTypes(List<String> values, String actor) {
        var selected = values == null ? Set.<String>of() : Set.copyOf(values);
        if (!SOURCE_OPTIONS.containsAll(selected)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown or restricted AWS source risk type");
        var row = permits.locked();
        if (row == null) throw new IllegalStateException("AWS permit control row is missing");
        row.sourceRiskTypes = String.join(",", new TreeSet<>(selected));
        String revision = RuleRevision.definition("aws-source-policy", "v1").field("types", row.sourceRiskTypes).hash();
        audit.save(new AwsSecurityAudit("source-policy-changed", actor, "source-policy:" + revision.substring(0, 32)));
    }
    /** Turning on allows every non-secret risk type; off clears the list. An unchanged switch writes nothing. */
    @Transactional
    public boolean saveSourceShown(boolean show, String actor) {
        if (show == sourceShown()) return false;
        saveSourceRiskTypes(show ? SOURCE_OPTIONS : List.of(), actor);
        return true;
    }
    String webAppUrl() { return webAppUrl; }
}
