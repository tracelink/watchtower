package com.tracelink.appsec.module.awssecurity;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;

/** Deployment-owned references. Normal scan requests cannot supply IAM roles or source URIs. */
@Component
public record AwsSecuritySettings(
        @Value("${watchtower.aws-security.region:}") String region,
        @Value("${watchtower.aws-security.account:}") String account,
        @Value("${watchtower.aws-security.space-id:}") String spaceId,
        @Value("${watchtower.aws-security.service-role:}") String serviceRole,
        @Value("${watchtower.aws-security.input-bucket:}") String inputBucket,
        @Value("${watchtower.aws-security.kms-key:}") String kmsKey,
        @Value("${watchtower.aws-security.log-group:}") String logGroup,
        @Value("${watchtower.aws-security.installation:watchtower}") String installation,
        @Value("${watchtower.aws-security.queue-url:}") String queueUrl,
        @Value("${watchtower.aws-security.review-seconds:14400}") long reviewSeconds) {
    public String unavailable() {
        return configurationIssue();
    }
    public String configurationIssue() {
        if (!account.matches("[0-9]{12}") || region.isBlank() || spaceId.isBlank()
                || !serviceRole.startsWith("arn:aws:iam::" + account + ":role/")
                || inputBucket.isBlank() || (!kmsKey.isBlank() && !kmsKey.startsWith("arn:aws:kms:" + region + ":" + account + ":key/"))
                || !queueUrl.startsWith("https://sqs." + region + ".amazonaws.com/" + account + "/") || !queueUrl.endsWith(".fifo")
                || !installation.matches("[A-Za-z0-9_-]{1,64}") || reviewSeconds < 60 || reviewSeconds > 14400) return "AWS connection settings are missing or invalid. Open AWS setup to check the account, region, workspace, role, storage and queue settings.";
        return null;
    }
    public Profile profile() { return new Profile("default", account, region, spaceId, serviceRole, inputBucket, kmsKey, logGroup, installation); }
    public record Profile(String id, String account, String region, String spaceId, String serviceRole,
            String bucket, String kmsKey, String logGroup, String installation) {
        /** An absent key selects S3-managed encryption; a configured key always requires KMS. */
        public boolean usesKms() { return !kmsKey.isBlank(); }
        public String revision() {
            return RuleRevision.definition("aws-security-profile", "v1").field("account", account)
                .field("region", region).field("space", spaceId).field("role", serviceRole)
                .field("bucket", bucket).field("kms", kmsKey).field("logs", logGroup).field("installation", installation).hash();
        }
    }
}
