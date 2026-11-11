package com.tracelink.appsec.module.awssecurity;
import jakarta.persistence.*;

@Entity @Table(name="aws_security_audit")
public class AwsSecurityAudit {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    @Column(nullable=false,length=64) public String action;
    @Column(nullable=false,length=255) public String actor;
    @Column(name="resource_id",nullable=false,length=64) public String resourceId;
    @Column(name="occurred_at",nullable=false) public long occurredAt;
    protected AwsSecurityAudit() { }
    public AwsSecurityAudit(String action, String actor, String resourceId) {
        this.action=action; this.actor=actor; this.resourceId=resourceId; occurredAt=System.currentTimeMillis();
    }
}
