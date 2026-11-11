package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_review_items")
public class RuleReviewItemEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="review_id", nullable=false, length=36)
 public String reviewId;
 @Column(name="rule_id", nullable=false)
 public Long ruleId;
 @Column(name="revision", nullable=true, length=64)
 public String revision;
 @Column(name="owner", nullable=false, length=255)
 public String owner;
 @Column(name="status", nullable=false, length=24)
 public String status;
 @Column(name="reason", nullable=false, length=64)
 public String reason;
 @Column(name="recommendation", nullable=false, length=300)
 public String recommendation;
 @Column(name="evidence_type", nullable=true, length=24)
 public String evidenceType;
 @Column(name="evidence_id", nullable=true, length=64)
 public String evidenceId;
 @Column(name="session_id", nullable=true, length=36)
 public String sessionId;
 @Column(name="turn_id", nullable=true, length=36)
 public String turnId;
 @Column(name="outcome", nullable=false, length=300)
 public String outcome;
 @Column(name="created_at", nullable=false)
 public Long createdAt;
 @Column(name="updated_at", nullable=false)
 public Long updatedAt;
 @Column(name="version", nullable=false)
 public Long version;
 public RuleReviewItemEntity() { }
 public RuleReviewItemEntity(String reviewId, Long ruleId, String revision, String owner, String status, String reason, String recommendation, String evidenceType, String evidenceId, String sessionId, String turnId, String outcome, Long createdAt, Long updatedAt, Long version) {
  this.reviewId=reviewId;
  this.ruleId=ruleId;
  this.revision=revision;
  this.owner=owner;
  this.status=status;
  this.reason=reason;
  this.recommendation=recommendation;
  this.evidenceType=evidenceType;
  this.evidenceId=evidenceId;
  this.sessionId=sessionId;
  this.turnId=turnId;
  this.outcome=outcome;
  this.createdAt=createdAt;
  this.updatedAt=updatedAt;
  this.version=version;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("review_id",reviewId);
  values.put("rule_id",ruleId);
  values.put("revision",revision);
  values.put("owner",owner);
  values.put("status",status);
  values.put("reason",reason);
  values.put("recommendation",recommendation);
  values.put("evidence_type",evidenceType);
  values.put("evidence_id",evidenceId);
  values.put("session_id",sessionId);
  values.put("turn_id",turnId);
  values.put("outcome",outcome);
  values.put("created_at",createdAt);
  values.put("updated_at",updatedAt);
  values.put("version",version);
  return values;
 }
}
