package com.tracelink.appsec.module.awssecurity;

import jakarta.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

@Entity @Table(name = "aws_security_rules") @PrimaryKeyJoinColumn(name = "rule_id")
public class AwsSecurityRuleEntity extends RuleEntity {
    @Column(name = "profile", nullable = false, length = 64) private String profile = "default";
    public String getProfile() { return profile; }
    public void setProfile(String profile) { this.profile = profile; }
    public AwsSecurityRuleDto toDto() {
        var dto = new AwsSecurityRuleDto(); dto.setId(getId()); dto.setName(getName());
        dto.setPriority(getPriority()); dto.setProfile(profile); return withStewardship(dto);
    }
}
