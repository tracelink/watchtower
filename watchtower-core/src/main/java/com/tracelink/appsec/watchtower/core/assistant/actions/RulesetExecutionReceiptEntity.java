package com.tracelink.appsec.watchtower.core.assistant.actions;

import jakarta.persistence.*;

/** Persisted in the same transaction as configuration changes; survives conversation expiry. */
@Entity @Table(name="assistant_ruleset_receipts")
public class RulesetExecutionReceiptEntity {
 @Id @Column(name="change_set_id",length=36) public String changeSetId;
 @Column(nullable=false) public String actor;
 @Column(name="content_hash",nullable=false,length=64) public String contentHash;
 @Column(name="applied_at",nullable=false) public long appliedAt;
 @Lob @Column(name="receipt_json",nullable=false,columnDefinition="LONGTEXT") public String receiptJson;
 protected RulesetExecutionReceiptEntity() { }
 public RulesetExecutionReceiptEntity(String id,String actor,String hash,String json,long now){changeSetId=id;this.actor=actor;contentHash=hash;receiptJson=json;appliedAt=now;}
}
