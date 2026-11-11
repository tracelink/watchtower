package com.tracelink.appsec.module.awssecurity;
import jakarta.persistence.*;

@Entity @Table(name = "aws_security_repository_settings")
public class AwsSecurityRepositorySettings {
    public enum Permission {
        INHERIT("Use default — AWS scans not allowed"), DISABLED("Do not allow AWS scans"), ENABLED("Allow AWS scans");
        private final String label;
        Permission(String label) { this.label=label; }
        public String label() { return label; }
    }
    @Id @Column(name = "repository_id") public long repositoryId;
    @Version public long version;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 16) public Permission permission = Permission.INHERIT;
    @Column(nullable = false, length = 64) public String profile = "default";
    @Column(name = "updated_by", length = 255) public String updatedBy;
    @Column(name = "updated_at") public long updatedAt;
    @Column(name = "readiness_at") public long readinessAt;
    @Column(name = "readiness_ok") public boolean readinessOk;
    @Column(name = "readiness_reason", length = 512) public String readinessReason;
}
