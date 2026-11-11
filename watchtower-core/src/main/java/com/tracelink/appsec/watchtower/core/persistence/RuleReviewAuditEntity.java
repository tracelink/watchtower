package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_review_audit")
public class RuleReviewAuditEntity implements LedgerRecord {
 @jakarta.persistence.Id @GeneratedValue(strategy=GenerationType.IDENTITY) @Column(name="audit_id", nullable=false)
 public Long auditId;
 @Column(name="review_id", nullable=false, length=36)
 public String reviewId;
 @Column(name="status", nullable=false, length=24)
 public String status;
 @Column(name="actor", nullable=false, length=255)
 public String actor;
 @Column(name="outcome", nullable=false, length=300)
 public String outcome;
 @Column(name="changed_at", nullable=false)
 public Long changedAt;
 public RuleReviewAuditEntity() { }
 public RuleReviewAuditEntity(Long auditId, String reviewId, String status, String actor, String outcome, Long changedAt) {
  this.auditId=auditId;
  this.reviewId=reviewId;
  this.status=status;
  this.actor=actor;
  this.outcome=outcome;
  this.changedAt=changedAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("audit_id",auditId);
  values.put("review_id",reviewId);
  values.put("status",status);
  values.put("actor",actor);
  values.put("outcome",outcome);
  values.put("changed_at",changedAt);
  return values;
 }
}
