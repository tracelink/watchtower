package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="finding_feedback_audit")
public class FindingFeedbackAuditEntity implements LedgerRecord {
 @jakarta.persistence.Id @GeneratedValue(strategy=GenerationType.IDENTITY) @Column(name="audit_id", nullable=false)
 public Long auditId;
 @Column(name="occurrence_key", nullable=false, length=64)
 public String occurrenceKey;
 @Column(name="judgment", nullable=false, length=24)
 public String judgment;
 @Column(name="disposition", nullable=false, length=24)
 public String disposition;
 @Column(name="explanation", nullable=false, length=300)
 public String explanation;
 @Column(name="reviewer", nullable=false, length=255)
 public String reviewer;
 @Column(name="changed_at", nullable=false)
 public Long changedAt;
 public FindingFeedbackAuditEntity() { }
 public FindingFeedbackAuditEntity(Long auditId, String occurrenceKey, String judgment, String disposition, String explanation, String reviewer, Long changedAt) {
  this.auditId=auditId;
  this.occurrenceKey=occurrenceKey;
  this.judgment=judgment;
  this.disposition=disposition;
  this.explanation=explanation;
  this.reviewer=reviewer;
  this.changedAt=changedAt;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("audit_id",auditId);
  values.put("occurrence_key",occurrenceKey);
  values.put("judgment",judgment);
  values.put("disposition",disposition);
  values.put("explanation",explanation);
  values.put("reviewer",reviewer);
  values.put("changed_at",changedAt);
  return values;
 }
}
