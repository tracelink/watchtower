package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="metrics_processed_scan")
@IdClass(MetricsProcessedScanEntity.Id.class)
public class MetricsProcessedScanEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="scan_type", nullable=false, length=32)
 public String scanType;
 @jakarta.persistence.Id @Column(name="scan_id", nullable=false)
 public Long scanId;
 @jakarta.persistence.Id @Column(name="metric_kind", nullable=false, length=32)
 public String metricKind;
 public MetricsProcessedScanEntity() { }
 public MetricsProcessedScanEntity(String scanType, Long scanId, String metricKind) {
  this.scanType=scanType;
  this.scanId=scanId;
  this.metricKind=metricKind;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("scan_type",scanType);
  values.put("scan_id",scanId);
  values.put("metric_kind",metricKind);
  return values;
 }
 public static class Id implements Serializable {
  private static final long serialVersionUID=1L;
  public String scanType;
  public Long scanId;
  public String metricKind;
  public Id() { }
  public Id(String scanType, Long scanId, String metricKind) {
   this.scanType=scanType;
   this.scanId=scanId;
   this.metricKind=metricKind;
  }
  @Override public boolean equals(Object other) { return other instanceof Id id && Objects.equals(scanType,id.scanType) && Objects.equals(scanId,id.scanId) && Objects.equals(metricKind,id.metricKind); }
  @Override public int hashCode() { return Objects.hash(scanType,scanId,metricKind); }
 }
}
