package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;

import jakarta.persistence.*;

/** Internal persistence record; never serialized to clients. */
@Entity
@Table(name="bb_webhook_scope")
public class BBWebhookScopeEntity {
    @Id
    @Column(name="scope_id")
    String id;
    @Column(name="integration_id")
    long integrationId;
    @Column(name="scope_key")
    String scope;
    @Column(name="hooks_json",columnDefinition="MEDIUMTEXT")
    String hooksJson;
    @Column(name="checked_at")
    Long checkedAt;
    @Column(name="attempted_at")
    Long attemptedAt;
    @Column(name="error_code")
    String error;
    @Column(name="callback_hash")
    String callbackHash;
    @Column(name="owned_count")
    int ownedCount;
    @Column(name="active_owned_count")
    int activeOwnedCount;
    @Column(name="changed_by")
    String changedBy;
    @Column(name="changed_at")
    Long changedAt;
}
