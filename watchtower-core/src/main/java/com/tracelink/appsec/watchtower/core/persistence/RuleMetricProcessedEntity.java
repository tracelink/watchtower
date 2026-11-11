package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_metric_processed")
@IdClass(RuleMetricProcessedEntity.Id.class)
public class RuleMetricProcessedEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="scan_type", nullable=false, length=24)
 public String scanType;
 @jakarta.persistence.Id @Column(name="scan_id", nullable=false)
 public Long scanId;
 public RuleMetricProcessedEntity() { }
 public RuleMetricProcessedEntity(String scanType, Long scanId) {
  this.scanType=scanType;
  this.scanId=scanId;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("scan_type",scanType);
  values.put("scan_id",scanId);
  return values;
 }
 public static class Id implements Serializable {
  private static final long serialVersionUID=1L;
  public String scanType;
  public Long scanId;
  public Id() { }
  public Id(String scanType, Long scanId) {
   this.scanType=scanType;
   this.scanId=scanId;
  }
  @Override public boolean equals(Object other) { return other instanceof Id id && Objects.equals(scanType,id.scanType) && Objects.equals(scanId,id.scanId); }
  @Override public int hashCode() { return Objects.hash(scanType,scanId); }
 }
}
