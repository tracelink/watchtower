package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_metric_daily")
@IdClass(RuleMetricDailyEntity.Id.class)
public class RuleMetricDailyEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="scan_type", nullable=false, length=24)
 public String scanType;
 @jakarta.persistence.Id @Column(name="bucket_start", nullable=false)
 public Long bucketStart;
 @jakarta.persistence.Id @Column(name="identity_key", nullable=false, length=64)
 public String identityKey;
 @Column(name="rule_id", nullable=true)
 public Long ruleId;
 @Column(name="revision", nullable=true, length=64)
 public String revision;
 @Column(name="findings", nullable=false)
 public Long findings;
 @Column(name="blocking", nullable=false)
 public Long blocking;
 @Column(name="blocking_unknown", nullable=false)
 public Long blockingUnknown;
 @Column(name="scans", nullable=false)
 public Long scans;
 public RuleMetricDailyEntity() { }
 public RuleMetricDailyEntity(String scanType, Long bucketStart, String identityKey, Long ruleId, String revision, Long findings, Long blocking, Long blockingUnknown, Long scans) {
  this.scanType=scanType;
  this.bucketStart=bucketStart;
  this.identityKey=identityKey;
  this.ruleId=ruleId;
  this.revision=revision;
  this.findings=findings;
  this.blocking=blocking;
  this.blockingUnknown=blockingUnknown;
  this.scans=scans;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("scan_type",scanType);
  values.put("bucket_start",bucketStart);
  values.put("identity_key",identityKey);
  values.put("rule_id",ruleId);
  values.put("revision",revision);
  values.put("findings",findings);
  values.put("blocking",blocking);
  values.put("blocking_unknown",blockingUnknown);
  values.put("scans",scans);
  return values;
 }
 public static class Id implements Serializable {
  private static final long serialVersionUID=1L;
  public String scanType;
  public Long bucketStart;
  public String identityKey;
  public Id() { }
  public Id(String scanType, Long bucketStart, String identityKey) {
   this.scanType=scanType;
   this.bucketStart=bucketStart;
   this.identityKey=identityKey;
  }
  @Override public boolean equals(Object other) { return other instanceof Id id && Objects.equals(scanType,id.scanType) && Objects.equals(bucketStart,id.bucketStart) && Objects.equals(identityKey,id.identityKey); }
  @Override public int hashCode() { return Objects.hash(scanType,bucketStart,identityKey); }
 }
}
