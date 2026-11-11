package com.tracelink.appsec.watchtower.core.persistence;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.*;

/** Typed persistence record; API maps retain the established column names. */
@Entity @Table(name="metrics_scan_daily")
@IdClass(MetricsScanDailyEntity.Id.class)
public class MetricsScanDailyEntity implements LedgerRecord {
 @jakarta.persistence.Id @Column(name="scan_type", nullable=false, length=32)
 public String scanType;
 @jakarta.persistence.Id @Column(name="bucket_start", nullable=false)
 public Long bucketStart;
 @Column(name="scan_count", nullable=false)
 public Long scanCount;
 @Column(name="violation_count", nullable=false)
 public Long violationCount;
 @Column(name="duration_sum_ms", nullable=false)
 public Long durationSumMs;
 @Column(name="duration_count", nullable=false)
 public Long durationCount;
 @Column(name="source_size_sum_bytes", nullable=false)
 public Long sourceSizeSumBytes;
 @Column(name="source_size_count", nullable=false)
 public Long sourceSizeCount;
 @Column(name="total_duration_sum_ms", nullable=false)
 public Long totalDurationSumMs;
 @Column(name="queue_duration_sum_ms", nullable=false)
 public Long queueDurationSumMs;
 @Column(name="source_duration_sum_ms", nullable=false)
 public Long sourceDurationSumMs;
 @Column(name="scanner_duration_sum_ms", nullable=false)
 public Long scannerDurationSumMs;
 @Column(name="processing_duration_sum_ms", nullable=false)
 public Long processingDurationSumMs;
 @Column(name="scm_duration_sum_ms", nullable=false)
 public Long scmDurationSumMs;
 @Column(name="persistence_duration_sum_ms", nullable=false)
 public Long persistenceDurationSumMs;
 @Column(name="cleanup_duration_sum_ms", nullable=false)
 public Long cleanupDurationSumMs;
 @Column(name="performance_count", nullable=false)
 public Long performanceCount;
 public MetricsScanDailyEntity() { }
 public MetricsScanDailyEntity(String scanType, Long bucketStart, Long scanCount, Long violationCount, Long durationSumMs, Long durationCount, Long sourceSizeSumBytes, Long sourceSizeCount, Long totalDurationSumMs, Long queueDurationSumMs, Long sourceDurationSumMs, Long scannerDurationSumMs, Long processingDurationSumMs, Long scmDurationSumMs, Long persistenceDurationSumMs, Long cleanupDurationSumMs, Long performanceCount) {
  this.scanType=scanType;
  this.bucketStart=bucketStart;
  this.scanCount=scanCount;
  this.violationCount=violationCount;
  this.durationSumMs=durationSumMs;
  this.durationCount=durationCount;
  this.sourceSizeSumBytes=sourceSizeSumBytes;
  this.sourceSizeCount=sourceSizeCount;
  this.totalDurationSumMs=totalDurationSumMs;
  this.queueDurationSumMs=queueDurationSumMs;
  this.sourceDurationSumMs=sourceDurationSumMs;
  this.scannerDurationSumMs=scannerDurationSumMs;
  this.processingDurationSumMs=processingDurationSumMs;
  this.scmDurationSumMs=scmDurationSumMs;
  this.persistenceDurationSumMs=persistenceDurationSumMs;
  this.cleanupDurationSumMs=cleanupDurationSumMs;
  this.performanceCount=performanceCount;
 }
 @Override public Map<String,Object> values() {
  Map<String,Object> values=new LinkedHashMap<>();
  values.put("scan_type",scanType);
  values.put("bucket_start",bucketStart);
  values.put("scan_count",scanCount);
  values.put("violation_count",violationCount);
  values.put("duration_sum_ms",durationSumMs);
  values.put("duration_count",durationCount);
  values.put("source_size_sum_bytes",sourceSizeSumBytes);
  values.put("source_size_count",sourceSizeCount);
  values.put("total_duration_sum_ms",totalDurationSumMs);
  values.put("queue_duration_sum_ms",queueDurationSumMs);
  values.put("source_duration_sum_ms",sourceDurationSumMs);
  values.put("scanner_duration_sum_ms",scannerDurationSumMs);
  values.put("processing_duration_sum_ms",processingDurationSumMs);
  values.put("scm_duration_sum_ms",scmDurationSumMs);
  values.put("persistence_duration_sum_ms",persistenceDurationSumMs);
  values.put("cleanup_duration_sum_ms",cleanupDurationSumMs);
  values.put("performance_count",performanceCount);
  return values;
 }
 public static class Id implements Serializable {
  private static final long serialVersionUID=1L;
  public String scanType;
  public Long bucketStart;
  public Id() { }
  public Id(String scanType, Long bucketStart) {
   this.scanType=scanType;
   this.bucketStart=bucketStart;
  }
  @Override public boolean equals(Object other) { return other instanceof Id id && Objects.equals(scanType,id.scanType) && Objects.equals(bucketStart,id.bucketStart); }
  @Override public int hashCode() { return Objects.hash(scanType,bucketStart); }
 }
}
