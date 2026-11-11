package com.tracelink.appsec.module.awssecurity;

import com.tracelink.appsec.watchtower.core.rule.*;

/** A service policy, not an individual AWS detector. Profile binding is installation-local. */
public class AwsSecurityRuleDto extends ProvidedRuleDto {
    private String profile = "default";
    public String getProfile() { return profile; }
    public void setProfile(String profile) { this.profile = profile; }
    public String getModule() { return AwsSecurityModule.NAME; }
    public String getMessage() { return "AI security assessment; provider coverage and evidence limits apply."; }
    public String getExternalUrl() { return "https://docs.aws.amazon.com/securityagent/latest/userguide/what-is.html"; }
    public String getExternalRuleKey() { return "security-review"; }
    protected RuleRevision executableDefinition() {
        return newDefinition().field("profile", profile).field("source", "S3")
                .field("validation", "DISABLED").field("remediation", "DISABLED");
    }
    public AwsSecurityRuleEntity toEntity() {
        var entity = new AwsSecurityRuleEntity();
        entity.setName(getName()); entity.setAuthor(getAuthor()); entity.setPriority(getPriority());
        entity.setMessage(getMessage()); entity.setExternalUrl(getExternalUrl()); entity.setProfile(profile);
        return entity;
    }
}
