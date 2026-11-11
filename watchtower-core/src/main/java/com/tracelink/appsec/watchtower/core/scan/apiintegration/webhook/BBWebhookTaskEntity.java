package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;

import jakarta.persistence.*;

/** Internal persistence record; never serialized to clients. */
@Entity
@Table(name="bb_webhook_task")
public class BBWebhookTaskEntity {
    @Id
    @Column(name="task_id")
    String id;
    @Column(name="operation_id")
    String operationId;
    @Column(name="scope_key")
    String scope;
    @Column(name="hook_uuid")
    String hookUuid;
    @Column(name="status")
    String status;
    @Column(name="result_code")
    String result;
    @Column(name="finished_at")
    Long finishedAt;
}
