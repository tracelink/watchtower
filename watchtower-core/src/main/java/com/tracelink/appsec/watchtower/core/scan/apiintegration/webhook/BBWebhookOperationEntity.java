package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;

import jakarta.persistence.*;

/** Internal persistence record; never serialized to clients. */
@Entity
@Table(name="bb_webhook_operation")
public class BBWebhookOperationEntity {
    @Id
    @Column(name="operation_id")
    String id;
    @Column(name="integration_id")
    long integrationId;
    @Column(name="action")
    String action;
    @Column(name="workspace_name") String workspace;
    @Column(name="callback_hash") String callbackHash;
    @Column(name="preset")
    String preset;
    @Column(name="active")
    boolean active;
    @Column(name="actor")
    String actor;
    @Column(name="created_at")
    long createdAt;
    @Column(name="job_id")
    Long jobId;
    @Column(name="status")
    String status;
}
