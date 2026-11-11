package com.tracelink.appsec.module.awssecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.module.awssecurity.AwsPrDecision.FailurePolicy;

/**
 * What happens to a pull request when AWS cannot finish its review (it fails, times out or cannot start): it passes
 * ({@link FailurePolicy#PASS_ON_ERROR}, the default, so a broken AWS never blocks developers) or stays marked incomplete
 * ({@link FailurePolicy#KEEP_INCOMPLETE}). Findings from Watchtower's own scanners block either way. The choice is made on the
 * AWS settings page and stored in the database; the deployment property only supplies the starting value.
 */
@Component
public class AwsSecurityFailurePolicyStore {
    private final FailurePolicy deploymentDefault;
    @Autowired(required = false) private AwsSecurityPermitRepository permits;
    @Autowired(required = false) private AwsSecurityAuditRepository audit;

    public AwsSecurityFailurePolicyStore(@Value("${watchtower.aws-security.failure-policy:PASS_ON_ERROR}") FailurePolicy deploymentDefault) {
        // "Undecided" was a placeholder before the choice had a setting; it now means the default.
        this.deploymentDefault = deploymentDefault == FailurePolicy.UNDECIDED ? FailurePolicy.PASS_ON_ERROR : deploymentDefault;
    }

    /** The policy in force: the saved choice, else the deployment default. */
    public FailurePolicy current() {
        if (permits == null) return deploymentDefault;
        var row = permits.findById(1).orElse(null);
        if (row == null || row.failurePolicy == null) return deploymentDefault;
        try {
            var saved = FailurePolicy.valueOf(row.failurePolicy);
            return saved == FailurePolicy.UNDECIDED ? deploymentDefault : saved;
        } catch (IllegalArgumentException unknown) { return deploymentDefault; }
    }

    /** The setup page's switch: on means a pull request passes when AWS cannot finish. */
    public boolean passOnError() { return current() == FailurePolicy.PASS_ON_ERROR; }

    /** Saves the switch; true when it changed. An unchanged switch writes nothing. */
    @Transactional
    public boolean savePassOnError(boolean pass, String actor) {
        if (pass == passOnError()) return false;
        var row = permits.locked();
        if (row == null) throw new IllegalStateException("AWS permit control row is missing");
        row.failurePolicy = (pass ? FailurePolicy.PASS_ON_ERROR : FailurePolicy.KEEP_INCOMPLETE).name();
        audit.save(new AwsSecurityAudit("failure-policy-changed", actor, "failure-policy:" + row.failurePolicy));
        return true;
    }
}
