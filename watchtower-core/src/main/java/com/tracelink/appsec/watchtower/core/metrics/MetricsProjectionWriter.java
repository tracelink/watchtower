package com.tracelink.appsec.watchtower.core.metrics;

import java.util.*;
import java.util.stream.Collectors;
import java.time.Instant;
import java.time.ZoneId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import io.micrometer.core.instrument.MeterRegistry;

/** Maintains dashboard projections in an independent, idempotent Hibernate transaction. */
@Service
public class MetricsProjectionWriter {
 private static final Logger LOG=LoggerFactory.getLogger(MetricsProjectionWriter.class);
 private final LedgerRepository records;private final MeterRegistry meters;private final ZoneId metricsZone;
 public MetricsProjectionWriter(LedgerRepository records,MeterRegistry meters,@Value("${watchtower.metrics.zone:UTC}")String metricsZone){this.records=records;this.meters=meters;this.metricsZone=ZoneId.of(metricsZone);}
 @Transactional(propagation=Propagation.REQUIRES_NEW)
 public void record(String scanType,AbstractScanEntity<?,?> scan,List<? extends AbstractScanViolationEntity<?>> violations){
  if(scan.getStatus()!=com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE||scan.getEndDateMillis()<=0)return;
  Map<String,Long> byName=violations.stream().filter(v->!RulePriority.INFORMATIONAL.equals(v.getSeverity())).collect(Collectors.groupingBy(AbstractScanViolationEntity::getViolationName,Collectors.counting()));
  recordSummary(scanType,scan.getId(),scan.getStartDateMillis(),scan.getEndDateMillis(),byName,scan instanceof PullRequestScanEntity pr?pr.getSourceSizeBytes():0);
 }
 @Transactional(propagation=Propagation.REQUIRES_NEW)
 public void recordSummary(String scanType,long scanId,long startMillis,long endMillis,Map<String,Long> byName,long sourceSize){
  if(!claim(scanType,scanId,"result"))return;
  long bucket=bucketStart(endMillis);var daily=daily(scanType,bucket);
  daily.scanCount++;daily.violationCount+=byName.values().stream().mapToLong(Long::longValue).sum();
  daily.durationSumMs+=Math.max(0,endMillis-startMillis);daily.durationCount++;
  daily.sourceSizeSumBytes+=sourceSize;daily.sourceSizeCount+=sourceSize>0?1:0;
  byName.forEach((name,count)->{
   var id=new MetricsViolationDailyEntity.Id(scanType,bucket,name);var metric=records.find(MetricsViolationDailyEntity.class,id);
   if(metric==null)records.insert(new MetricsViolationDailyEntity(scanType,bucket,name,count));else metric.violationCount+=count;
  });
  if("pull_request".equals(scanType))refreshPrDimensions();
 }
 @Transactional(propagation=Propagation.REQUIRES_NEW)
 public void recordPrPerformance(PullRequestScanEntity scan){
  if(!scan.isPerformanceComplete()||!claim("pull_request",scan.getId(),"performance"))return;
  var daily=daily("pull_request",bucketStart(scan.getEndDateMillis()));
  daily.totalDurationSumMs+=scan.getTotalDurationMs();daily.queueDurationSumMs+=scan.getQueueWaitDurationMs();
  daily.sourceDurationSumMs+=scan.getSourcePreparationDurationMs();daily.scannerDurationSumMs+=scan.getScannerExecutionDurationMs();
  daily.processingDurationSumMs+=scan.getResultProcessingDurationMs();daily.scmDurationSumMs+=scan.getScmReportingDurationMs();
  daily.persistenceDurationSumMs+=scan.getPersistenceDurationMs();daily.cleanupDurationSumMs+=scan.getCleanupDurationMs();daily.performanceCount++;
 }
 /**
  * The time an AWS review kept a pull request open after its local result was saved. The scan was counted when that result was
  * saved, so its duration (and the speed breakdown's totals) grow by the wait, once: a marker makes a repeat a no-op. Averages then
  * show how long scans really took, not just how long Watchtower's own scanners took.
  */
 @Transactional(propagation=Propagation.REQUIRES_NEW)
 public void recordProviderWait(long scanId,long localEndMillis,long extraMillis,boolean performanceRecorded){
  if(extraMillis<=0||records.find(MetricsProcessedScanEntity.class,new MetricsProcessedScanEntity.Id("pull_request",scanId,"result"))==null||!claim("pull_request",scanId,"provider-wait"))return;
  var daily=daily("pull_request",bucketStart(localEndMillis));
  daily.durationSumMs+=extraMillis;
  if(performanceRecorded){daily.totalDurationSumMs+=extraMillis;daily.scannerDurationSumMs+=extraMillis;}
 }
 /** The same projection lock serializes dry-run snapshots, repair and ordinary persistence. */
 public enum ReconcileType {
  PULL_REQUEST("pull_request",PullRequestScanEntity.class,"PullRequestScanEntity"),
  UPLOAD("upload",com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity.class,"UploadScanEntity"),
  CONTAINER("container",com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity.class,"ImageScanEntity");
  final String key;final Class<? extends AbstractScanEntity> entity;final String entityName;
  ReconcileType(String key,Class<? extends AbstractScanEntity> entity,String entityName){this.key=key;this.entity=entity;this.entityName=entityName;}
 }
 public record Reconciliation(String scanType,Map<String,Long> sourceStates,long successfulProcessing,long projectedProcessing,
   long processedResults,long orphanedMarkers,String fingerprint,boolean repaired) { }
 @Transactional
 public Reconciliation reconcile(ReconcileType type,String expectedFingerprint) {
  records.lockScope("metrics-projections");
  var states=new TreeMap<String,Long>();long successful=0,last=0;
  var digest=com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory.hash(type.name());
  while(true) {
   var batch=records.list(type.entity,"SELECT s FROM "+type.entityName+" s WHERE s.id>?1 ORDER BY s.id",0,500,last);
   if(batch.isEmpty())break;
   for(AbstractScanEntity<?,?> scan:batch) {
    last=scan.getId();states.merge(Objects.toString(scan.getStatus(),"UNKNOWN"),1L,Long::sum);
    if(scan.getStatus()==com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE&&scan.getEndDateMillis()>0)successful++;
    digest=com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory.hash(digest+":"+last+":"+scan.getStatus()+":"+scan.getStartDateMillis()+":"+scan.getEndDateMillis());
   }
  }
  long projected=records.scalar(Long.class,"SELECT COALESCE(SUM(m.scanCount),0) FROM MetricsScanDailyEntity m WHERE m.scanType=?1",type.key);
  long markers=records.scalar(Long.class,"SELECT COUNT(m) FROM MetricsProcessedScanEntity m WHERE m.scanType=?1 AND m.metricKind='result'",type.key);
  long orphaned=records.scalar(Long.class,"SELECT COUNT(m) FROM MetricsProcessedScanEntity m WHERE m.scanType=?1 AND NOT EXISTS (SELECT s.id FROM "+type.entityName+" s WHERE s.id=m.scanId)",type.key);
  String fingerprint=com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory.hash(digest+":"+projected+":"+markers+":"+orphaned);
  if(expectedFingerprint==null)return new Reconciliation(type.key,Map.copyOf(states),successful,projected,markers,orphaned,fingerprint,false);
  if(!fingerprint.equals(expectedFingerprint))throw new IllegalStateException("Source records changed after the dry run. Review a fresh dry run before repair.");
  if(orphaned>0)throw new IllegalStateException("Some source records have expired. Their retained metrics cannot be reconstructed; no data was changed.");
  // Only derived rows are replaced. Source scan records and immutable artifacts are untouched.
  records.update("DELETE FROM MetricsProcessedScanEntity m WHERE m.scanType=?1",type.key);
  records.update("DELETE FROM MetricsViolationDailyEntity m WHERE m.scanType=?1",type.key);
  records.update("DELETE FROM MetricsScanDailyEntity m WHERE m.scanType=?1",type.key);
  last=0;
  while(true) {
   var batch=records.list(type.entity,"SELECT s FROM "+type.entityName+" s WHERE s.id>?1 ORDER BY s.id",0,500,last);
   if(batch.isEmpty())break;
   for(AbstractScanEntity<?,?> scan:batch) {
    last=scan.getId();
    if(scan.getStatus()!=com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE||scan.getEndDateMillis()<=0)continue;
    record(type.key,scan,scan.getViolations());
    if(scan instanceof PullRequestScanEntity pr){
     recordPrPerformance(pr);
     // A repair rebuilds from the scan records, so the AWS wait comes back from the saved provider times.
     recordProviderWait(pr.getId(),pr.getEndDateMillis(),com.tracelink.appsec.watchtower.core.scan.presentation.ProviderTiming.ofJson(pr.getEndDateMillis(),pr.getProviderSummaryJson()).extraMs(),pr.isPerformanceComplete());
    }
   }
  }
  records.flush();
  return new Reconciliation(type.key,Map.copyOf(states),successful,successful,successful,0,fingerprint,true);
 }
 public void recordFailure(String scanType,RuntimeException failure){meters.counter("watchtower.metrics.projection.failures").increment();LOG.error("Dashboard projection update failed for scan type {}",scanType,failure);}
 private boolean claim(String type,long scanId,String kind){
  records.lockScope("metrics-projections");var id=new MetricsProcessedScanEntity.Id(type,scanId,kind);
  if(records.find(MetricsProcessedScanEntity.class,id)!=null)return false;
  records.insert(new MetricsProcessedScanEntity(type,scanId,kind));return true;
 }
 private MetricsScanDailyEntity daily(String type,long bucket){
  var metric=records.find(MetricsScanDailyEntity.class,new MetricsScanDailyEntity.Id(type,bucket));
  return metric!=null?metric:records.insert(new MetricsScanDailyEntity(type,bucket,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L));
 }
 private long bucketStart(long timestamp){return Instant.ofEpochMilli(timestamp).atZone(metricsZone).toLocalDate().atStartOfDay(metricsZone).toInstant().toEpochMilli();}
 private void refreshPrDimensions(){
  dimension("pull_request_count",records.scalar(Long.class,"SELECT COUNT(c) FROM PullRequestContainerEntity c"));
  dimension("repository_count",records.scalar(Long.class,"SELECT COUNT(r) FROM RepositoryEntity r WHERE r.scanType=?1 AND r.lastReviewedDate>0",CodeScanType.PULL_REQUEST));
 }
 private void dimension(String key,long value){
  var metric=records.find(MetricsDimensionSummaryEntity.class,key);
  if(metric==null)records.insert(new MetricsDimensionSummaryEntity(key,value));else metric.metricValue=value;
 }
}
