package com.tracelink.appsec.module.awssecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Shared AWS admission limit. The deployment value is used until an administrator saves an override. */
@Component
public class AwsSecurityCapacity {
    private final int deploymentDefault;
    private final AwsSecurityPermitRepository permits;
    private final AwsSecurityAuditRepository audit;

    @Autowired
    public AwsSecurityCapacity(@Value("${watchtower.aws-security.max-concurrent-reviews:2}") int deploymentDefault,
                               AwsSecurityPermitRepository permits, AwsSecurityAuditRepository audit) {
        validate(deploymentDefault);
        this.deploymentDefault = deploymentDefault;
        this.permits = permits;
        this.audit = audit;
    }

    // Keeps isolated admission tests independent of persistence infrastructure.
    AwsSecurityCapacity(int deploymentDefault) {
        this(deploymentDefault, null, null);
    }

    public record Snapshot(int limit, int deploymentDefault, boolean overridden) { }

    public Snapshot snapshot() {
        if (permits == null) return new Snapshot(deploymentDefault, deploymentDefault, false);
        var control = permits.findById(1).orElseThrow(() -> new IllegalStateException("AWS permit control row is missing"));
        return new Snapshot(limit(control), deploymentDefault, control.configuredLimit != null);
    }

    public int limit() {
        return snapshot().limit();
    }

    public int deploymentDefault() {
        return deploymentDefault;
    }

    int limit(AwsSecurityPermit control) {
        return control.configuredLimit == null ? deploymentDefault : control.configuredLimit;
    }

    @Transactional
    public void save(int limit, String actor) {
        if (limit < 1 || limit > 5) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Concurrent AWS reviews must be between 1 and 5");
        var control = permits.locked();
        if (control == null) throw new IllegalStateException("AWS permit control row is missing");
        control.configuredLimit = limit;
        audit.save(new AwsSecurityAudit("capacity-changed", actor, "concurrent-reviews:" + limit));
    }

    private static void validate(int limit) {
        if (limit < 1 || limit > 5) throw new IllegalArgumentException("AWS concurrent reviews must be between 1 and 5");
    }
}
