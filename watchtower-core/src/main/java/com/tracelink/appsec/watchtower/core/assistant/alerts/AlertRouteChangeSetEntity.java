package com.tracelink.appsec.watchtower.core.assistant.alerts;

import jakarta.persistence.*;

/** A drafted set of alert-route changes awaiting a person's approval. Route settings only; never a URL or source. */
@Entity
@Table(name="alert_route_change_set",uniqueConstraints=@UniqueConstraint(columnNames={"owner","request_key"}))
public class AlertRouteChangeSetEntity {
 public static final long LIFETIME_MILLIS=30*60*1000L;
 @Id @Column(length=36) public String id;
 @Column(nullable=false) public String owner;
 @Column(name="request_key",nullable=false,length=36) public String requestKey;
 @Column(name="created_turn_id",length=36) public String createdTurnId;
 @Version public long version;
 @Column(nullable=false,length=16) public String status;
 @Column(name="content_hash",nullable=false,length=64) public String contentHash;
 @Column(name="request_hash",nullable=false,length=64) public String requestHash;
 @Lob @Column(name="request_json",nullable=false,columnDefinition="LONGTEXT") public String requestJson;
 @Lob @Column(name="preview_json",nullable=false,columnDefinition="LONGTEXT") public String previewJson;
 @Lob @Column(name="receipt_json",columnDefinition="LONGTEXT") public String receiptJson;
 @Column(name="created_at",nullable=false) public long createdAt;
 @Column(name="expires_at",nullable=false) public long expiresAt;
 @Column(name="applied_at") public Long appliedAt;
 protected AlertRouteChangeSetEntity() { }
 public AlertRouteChangeSetEntity(String id,String owner,String requestKey,String turnId,String requestJson,String requestHash,String previewJson,String contentHash,long now) {
  this.id=id;this.owner=owner;this.requestKey=requestKey;createdTurnId=turnId;this.requestJson=requestJson;this.requestHash=requestHash;
  this.previewJson=previewJson;this.contentHash=contentHash;createdAt=now;expiresAt=now+LIFETIME_MILLIS;status="DRAFT";
 }
}
