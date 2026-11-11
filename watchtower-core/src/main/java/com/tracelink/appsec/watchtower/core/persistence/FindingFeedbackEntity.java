package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="finding_feedback")
public class FindingFeedbackEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="occurrence_key", nullable=false, length=64)
 public String occurrenceKey;
 @Column(name="scan_type", nullable=false, length=24)
 public String scanType;
 @Column(name="scan_id", nullable=false)
 public Long scanId;
 @Column(name="finding_key", nullable=false, length=64)
 public String findingKey;
 @Column(name="rule_id", nullable=true)
 public Long ruleId;
 @Column(name="revision", nullable=true, length=64)
 public String revision;
 @Column(name="effective_blocking", nullable=true)
 public Boolean effectiveBlocking;
 @Column(name="occurred_at", nullable=false)
 public Long occurredAt;
 @Column(name="judgment", nullable=false, length=24)
 public String judgment;
 @Column(name="disposition", nullable=false, length=24)
 public String disposition;
 @Column(name="explanation", nullable=false, length=300)
 public String explanation;
 @Column(name="reviewer", nullable=false, length=255)
 public String reviewer;
 @Column(name="updated_at", nullable=false)
 public Long updatedAt;
 @Column(name="version", nullable=false)
 public Long version;
 public FindingFeedbackEntity() { }
 public FindingFeedbackEntity(String occurrenceKey, String scanType, Long scanId, String findingKey, Long ruleId, String revision, Boolean effectiveBlocking, Long occurredAt, String judgment, String disposition, String explanation, String reviewer, Long updatedAt, Long version) {
  this.occurrenceKey=occurrenceKey;
  this.scanType=scanType;
  this.scanId=scanId;
  this.findingKey=findingKey;
  this.ruleId=ruleId;
  this.revision=revision;
  this.effectiveBlocking=effectiveBlocking;
  this.occurredAt=occurredAt;
  this.judgment=judgment;
  this.disposition=disposition;
  this.explanation=explanation;
  this.reviewer=reviewer;
  this.updatedAt=updatedAt;
  this.version=version;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("occurrence_key",occurrenceKey);
  values.put("scan_type",scanType);
  values.put("scan_id",scanId);
  values.put("finding_key",findingKey);
  values.put("rule_id",ruleId);
  values.put("revision",revision);
  values.put("effective_blocking",effectiveBlocking);
  values.put("occurred_at",occurredAt);
  values.put("judgment",judgment);
  values.put("disposition",disposition);
  values.put("explanation",explanation);
  values.put("reviewer",reviewer);
  values.put("updated_at",updatedAt);
  values.put("version",version);
  return values;
 }
}
