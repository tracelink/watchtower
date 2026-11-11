package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_health")
@IdClass(RuleHealthEntity.Id.class)
public class RuleHealthEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="rule_id", nullable=false)
 public Long ruleId;
 @jakarta.persistence.Id @Column(name="revision_key", nullable=false, length=64)
 public String revisionKey;
 @Column(name="computed_at", nullable=false)
 public Long computedAt;
 @Column(name="evidence_json", nullable=false, columnDefinition="TEXT")
 public String evidenceJson;
 public RuleHealthEntity() { }
 public RuleHealthEntity(Long ruleId, String revisionKey, Long computedAt, String evidenceJson) {
  this.ruleId=ruleId;
  this.revisionKey=revisionKey;
  this.computedAt=computedAt;
  this.evidenceJson=evidenceJson;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("rule_id",ruleId);
  values.put("revision_key",revisionKey);
  values.put("computed_at",computedAt);
  values.put("evidence_json",evidenceJson);
  return values;
 }
 public static class Id implements Serializable {
  private static final long serialVersionUID=1L;
  public Long ruleId;
  public String revisionKey;
  public Id() { }
  public Id(Long ruleId, String revisionKey) {
   this.ruleId=ruleId;
   this.revisionKey=revisionKey;
  }
  @Override public boolean equals(Object other) { return other instanceof Id id && Objects.equals(ruleId,id.ruleId) && Objects.equals(revisionKey,id.revisionKey); }
  @Override public int hashCode() { return Objects.hash(ruleId,revisionKey); }
 }
}
