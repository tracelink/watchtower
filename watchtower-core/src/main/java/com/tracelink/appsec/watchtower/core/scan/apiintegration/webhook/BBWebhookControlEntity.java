package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;

import jakarta.persistence.*;
import com.tracelink.appsec.watchtower.core.encryption.converter.StringEncryptedAttributeConverter;

/** Internal persistence record; never serialized to clients. */
@Entity
@Table(name="bb_webhook_control")
public class BBWebhookControlEntity {
    @Id
    @Column(name="integration_id")
    long id;
    @Column(name="lease_owner")
    String owner;
    @Column(name="lease_until")
    long leaseUntil;
    @Convert(converter=StringEncryptedAttributeConverter.class)
    @Column(name="rotation_secret")
    String rotationSecret;
    @Column(name="rotation_operation")
    String rotationOperation;
    @Column(name="rotation_started_at")
    Long rotationStartedAt;
}
