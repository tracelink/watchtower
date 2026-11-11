package com.tracelink.appsec.watchtower.core.assistant.actions;

import jakarta.persistence.*;

/** Private, source-free approval manifest. JSON encodes the typed action contract, never source. */
@Entity
@Table(name="assistant_ruleset_change_sets", uniqueConstraints=@UniqueConstraint(columnNames={"owner","request_key"}))
public class RulesetChangeSetEntity {
 @Id @Column(length=36) public String id;
 @Column(nullable=false) public String owner;
 @Column(name="request_key",nullable=false,length=36) public String requestKey;
 @Column(name="turn_id",length=36) public String turnId;
 @Version public long version;
 @Column(nullable=false,length=20) public String status;
 @Column(name="content_hash",nullable=false,length=64) public String contentHash;
 @Column(name="request_hash",nullable=false,length=64) public String requestHash;
 @Lob @Column(name="request_json",nullable=false,columnDefinition="LONGTEXT") public String requestJson;
 @Lob @Column(name="preview_json",nullable=false,columnDefinition="LONGTEXT") public String previewJson;
 @Column(name="created_at",nullable=false) public long createdAt;
 @Column(name="expires_at",nullable=false) public long expiresAt;
 protected RulesetChangeSetEntity() { }
 public RulesetChangeSetEntity(String id,String owner,String key,String turn,String request,String preview,String hash,long now) {
  this.id=id;this.owner=owner;requestKey=key;turnId=turn;requestJson=request;previewJson=preview;
  contentHash=hash;requestHash=com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory.hash(request);
  createdAt=now;expiresAt=now+30*60*1000L;status="DRAFT";
 }
}
