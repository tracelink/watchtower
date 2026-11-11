package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="rule_metric_scan")
@IdClass(RuleMetricScanEntity.Id.class)
public class RuleMetricScanEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="scan_type", nullable=false, length=24)
 public String scanType;
 @jakarta.persistence.Id @Column(name="scan_id", nullable=false)
 public Long scanId;
 @jakarta.persistence.Id @Column(name="identity_key", nullable=false, length=64)
 public String identityKey;
 @Column(name="rule_id", nullable=true)
 public Long ruleId;
 @Column(name="revision", nullable=true, length=64)
 public String revision;
 @Column(name="module", nullable=true, length=64)
 public String module;
 @Column(name="bucket_start", nullable=false)
 public Long bucketStart;
 @Column(name="findings", nullable=false)
 public Long findings;
 @Column(name="blocking", nullable=false)
 public Long blocking;
 @Column(name="blocking_unknown", nullable=false)
 public Long blockingUnknown;
 @Column(name="opportunities", nullable=true)
 public Long opportunities;
 @Column(name="coverage", nullable=false, length=24)
 public String coverage;
 @Column(name="engine_status", nullable=false, length=24)
 public String engineStatus = "UNKNOWN";
 @Column(name="last_fired", nullable=true)
 public Long lastFired;
 public RuleMetricScanEntity() { }
 public RuleMetricScanEntity(String scanType, Long scanId, String identityKey, Long ruleId, String revision, String module, Long bucketStart, Long findings, Long blocking, Long blockingUnknown, Long opportunities, String coverage, Long lastFired) {
  this.scanType=scanType;
  this.scanId=scanId;
  this.identityKey=identityKey;
  this.ruleId=ruleId;
  this.revision=revision;
  this.module=module;
  this.bucketStart=bucketStart;
  this.findings=findings;
  this.blocking=blocking;
  this.blockingUnknown=blockingUnknown;
  this.opportunities=opportunities;
  this.coverage=coverage;
  this.lastFired=lastFired;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("scan_type",scanType);
  values.put("scan_id",scanId);
  values.put("identity_key",identityKey);
  values.put("rule_id",ruleId);
  values.put("revision",revision);
  values.put("module",module);
  values.put("bucket_start",bucketStart);
  values.put("findings",findings);
  values.put("blocking",blocking);
  values.put("blocking_unknown",blockingUnknown);
  values.put("opportunities",opportunities);
  values.put("coverage",coverage);
  values.put("last_fired",lastFired);
  return values;
 }
 public static class Id implements Serializable {
  private static final long serialVersionUID=1L;
  public String scanType;
  public Long scanId;
  public String identityKey;
  public Id() { }
  public Id(String scanType, Long scanId, String identityKey) {
   this.scanType=scanType;
   this.scanId=scanId;
   this.identityKey=identityKey;
  }
  @Override public boolean equals(Object other) { return other instanceof Id id && Objects.equals(scanType,id.scanType) && Objects.equals(scanId,id.scanId) && Objects.equals(identityKey,id.identityKey); }
  @Override public int hashCode() { return Objects.hash(scanType,scanId,identityKey); }
 }
}
