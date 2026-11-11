package com.tracelink.appsec.module.awssecurity;
import jakarta.persistence.*;

/** Durable remote slot. Unknown provider outcomes retain their slot after a worker lease expires. */
@Entity @Table(name = "aws_security_permit")
public class AwsSecurityPermit {
    @Id public int id;
    @Column(name = "run_id", length = 36) public String runId;
    @Column(name = "configured_limit") public Integer configuredLimit;
    @Column(name = "source_risk_types", length = 1000) public String sourceRiskTypes;
    @Column(name = "failure_policy", length = 24) public String failurePolicy;
}
