package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="metrics_violation_daily")
@IdClass(MetricsViolationDailyEntity.Id.class)
public class MetricsViolationDailyEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="scan_type", nullable=false, length=32)
 public String scanType;
 @jakarta.persistence.Id @Column(name="bucket_start", nullable=false)
 public Long bucketStart;
 @jakarta.persistence.Id @Column(name="violation_name", nullable=false, length=255)
 public String violationName;
 @Column(name="violation_count", nullable=false)
 public Long violationCount;
 public MetricsViolationDailyEntity() { }
 public MetricsViolationDailyEntity(String scanType, Long bucketStart, String violationName, Long violationCount) {
  this.scanType=scanType;
  this.bucketStart=bucketStart;
  this.violationName=violationName;
  this.violationCount=violationCount;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("scan_type",scanType);
  values.put("bucket_start",bucketStart);
  values.put("violation_name",violationName);
  values.put("violation_count",violationCount);
  return values;
 }
 public static class Id implements Serializable {
  private static final long serialVersionUID=1L;
  public String scanType;
  public Long bucketStart;
  public String violationName;
  public Id() { }
  public Id(String scanType, Long bucketStart, String violationName) {
   this.scanType=scanType;
   this.bucketStart=bucketStart;
   this.violationName=violationName;
  }
  @Override public boolean equals(Object other) { return other instanceof Id id && Objects.equals(scanType,id.scanType) && Objects.equals(bucketStart,id.bucketStart) && Objects.equals(violationName,id.violationName); }
  @Override public int hashCode() { return Objects.hash(scanType,bucketStart,violationName); }
 }
}
