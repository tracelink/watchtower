package com.tracelink.appsec.watchtower.core.metrics;

import java.time.*;
import java.util.*;
import org.springframework.stereotype.Repository;
import org.springframework.beans.factory.annotation.Value;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanPerformanceSummary;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference;

/** Read-only access to typed Hibernate dashboard projections. */
@Repository
public class MetricsProjectionRepository {
 private final LedgerRepository records;private final ZoneId metricsZone;
 public MetricsProjectionRepository(LedgerRepository records,@Value("${watchtower.metrics.zone:UTC}")String metricsZone){this.records=records;this.metricsZone=ZoneId.of(metricsZone);}
 public List<DailyScanMetric> findScans(String type,long start,long end){
  return records.list(MetricsScanDailyEntity.class,"SELECT m FROM MetricsScanDailyEntity m WHERE m.scanType=?1 AND m.bucketStart>=?2 AND m.bucketStart<?3 ORDER BY m.bucketStart",0,Integer.MAX_VALUE,type,start,end).stream().map(m->new DailyScanMetric(date(m.bucketStart),m.scanCount,m.violationCount,m.durationSumMs,m.durationCount,m.sourceSizeSumBytes,m.sourceSizeCount,m.performanceCount,m.totalDurationSumMs,m.queueDurationSumMs,m.sourceDurationSumMs,m.scannerDurationSumMs,m.processingDurationSumMs,m.scmDurationSumMs,m.persistenceDurationSumMs,m.cleanupDurationSumMs)).toList();
 }
 public List<DailyViolationMetric> findViolations(String type,long start,long end){
  var local=records.list(MetricsViolationDailyEntity.class,"SELECT m FROM MetricsViolationDailyEntity m WHERE m.scanType=?1 AND m.bucketStart>=?2 AND m.bucketStart<?3 ORDER BY m.bucketStart,m.violationName",0,Integer.MAX_VALUE,type,start,end).stream().map(m->new DailyViolationMetric(date(m.bucketStart),m.violationName,m.violationCount)).toList();
  if(!"repository".equals(type))return local;
  var combined=new ArrayList<>(local);combined.addAll(repositoryProviderViolations(start,end));return combined;
 }
 /** Remote results arrive after the local scan projection was written. Read their latest saved
  * summaries in bounded JPA pages so historical scans appear without a projection repair. */
 public List<DailyViolationMetric> repositoryProviderViolations(long start,long end){
  Map<LocalDateTime,Map<String,Long>> daily=new TreeMap<>();long lastId=0;
  while(true){
   var rows=records.maps("SELECT s.id AS id,s.endDate AS ended,s.providerSummaryJson AS summary FROM RepoScanEntity s WHERE s.id>?1 AND s.status=?2 AND s.endDate>=?3 AND s.endDate<?4 AND s.providerSummaryJson IS NOT NULL ORDER BY s.id",0,200,lastId,ScanStatus.DONE,start,end);
   if(rows.isEmpty())break;
   for(var row:rows){
    lastId=((Number)row.get("id")).longValue();
    LocalDateTime finished=date(((Number)row.get("ended")).longValue());
    var counts=daily.computeIfAbsent(finished.withHour(0).withMinute(0).withSecond(0).withNano(0),ignored->new TreeMap<>());
    var seen=new HashSet<String>();
    for(var reference:ProviderAssessmentReference.decode((String)row.get("summary"))){
     if(reference.status()==null||!seen.add(reference.runId()))continue;
     long count=reference.status().imported();
     var severities=reference.status().nativeSeverityCounts();
     if(severities!=null)count-=severities.getOrDefault("INFORMATIONAL",0)+severities.getOrDefault("INFO",0);
     if(count>0)counts.merge(reference.policyName()==null||reference.policyName().isBlank()?reference.provider():reference.policyName(),count,Long::sum);
    }
   }
   if(rows.size()<200)break;
  }
  return daily.entrySet().stream().flatMap(day->day.getValue().entrySet().stream()
   .map(rule->new DailyViolationMetric(day.getKey(),rule.getKey(),rule.getValue()))).toList();
 }
 public long repositoryProviderFindingCount(long start,long end){
  return repositoryProviderViolations(start,end).stream().mapToLong(DailyViolationMetric::count).sum();
 }
 public List<ScannerTimingMetric> findPrScannerTimings(long start,long end){
  return records.maps("SELECT s.endDate AS end_date,s.scannerTimingsJson AS timings FROM PullRequestScanEntity s WHERE s.performanceComplete=TRUE AND s.endDate>=?1 AND s.endDate<?2 AND s.scannerTimingsJson IS NOT NULL ORDER BY s.endDate",0,Integer.MAX_VALUE,start,end).stream().map(m->new ScannerTimingMetric(date(((Number)m.get("end_date")).longValue()),(String)m.get("timings"))).toList();
 }
 /** Watchtower scans cannot predate 2015; an earlier day comes from a bad clock or import and would
  * stretch All time charts by decades, so it is left out of the chart range and counted instead. */
 public static final long EARLIEST_PLAUSIBLE_SCAN_MILLIS=Instant.parse("2015-01-01T00:00:00Z").toEpochMilli();
 public LocalDateTime oldestDate(String type){Long oldest=records.scalar(Long.class,"SELECT MIN(m.bucketStart) FROM MetricsScanDailyEntity m WHERE m.scanType=?1 AND m.bucketStart>=?2",type,EARLIEST_PLAUSIBLE_SCAN_MILLIS);return oldest==null?LocalDateTime.now(metricsZone).minusDays(1):date(oldest);}
 /** Scans recorded before {@link #EARLIEST_PLAUSIBLE_SCAN_MILLIS}, which charts leave out. */
 public long implausibleScanCount(String type){Long count=records.scalar(Long.class,"SELECT COALESCE(SUM(m.scanCount),0) FROM MetricsScanDailyEntity m WHERE m.scanType=?1 AND m.bucketStart<?2",type,EARLIEST_PLAUSIBLE_SCAN_MILLIS);return count==null?0:count;}
 public long sum(String type,String column){
  String attribute=switch(column){case "scan_count"->"scanCount";case "violation_count"->"violationCount";default->throw new IllegalArgumentException("Unsupported projection column");};
  return records.scalar(Long.class,"SELECT COALESCE(SUM(m."+attribute+"),0) FROM MetricsScanDailyEntity m WHERE m.scanType=?1",type);
 }
 public double average(String type,String sumColumn,String countColumn){
  String sum=switch(sumColumn){case "duration_sum_ms"->"durationSumMs";case "source_size_sum_bytes"->"sourceSizeSumBytes";default->throw new IllegalArgumentException("Unsupported projection column");};
  String count=switch(countColumn){case "duration_count"->"durationCount";case "source_size_count"->"sourceSizeCount";default->throw new IllegalArgumentException("Unsupported projection column");};
  var values=records.maps("SELECT COALESCE(SUM(m."+sum+"),0) AS total,COALESCE(SUM(m."+count+"),0) AS samples FROM MetricsScanDailyEntity m WHERE m.scanType=?1",0,1,type).getFirst();
  long samples=((Number)values.get("samples")).longValue();return samples==0?0:((Number)values.get("total")).doubleValue()/samples;
 }
 public PRScanPerformanceSummary performanceSince(long since){
  var values=records.maps("SELECT COALESCE(SUM(m.performanceCount),0) AS samples,COALESCE(SUM(m.totalDurationSumMs),0) AS total,COALESCE(SUM(m.queueDurationSumMs),0) AS queue,COALESCE(SUM(m.sourceDurationSumMs),0) AS source,COALESCE(SUM(m.scannerDurationSumMs),0) AS scanner,COALESCE(SUM(m.processingDurationSumMs),0) AS processing,COALESCE(SUM(m.scmDurationSumMs),0) AS scm,COALESCE(SUM(m.persistenceDurationSumMs),0) AS persistence,COALESCE(SUM(m.cleanupDurationSumMs),0) AS cleanup FROM MetricsScanDailyEntity m WHERE m.scanType='pull_request' AND m.bucketStart>=?1",0,1,since).getFirst();
  long count=((Number)values.get("samples")).longValue();if(count==0)return PRScanPerformanceSummary.empty();
  return new PRScanPerformanceSummary(count,average(values,"total",count),average(values,"queue",count),average(values,"source",count),average(values,"scanner",count),average(values,"processing",count),average(values,"scm",count),average(values,"persistence",count),average(values,"cleanup",count));
 }
 public long dimension(String key){var metric=records.find(MetricsDimensionSummaryEntity.class,key);return metric==null?0:metric.metricValue;}
 private double average(Map<String,Object> values,String key,long count){return ((Number)values.get(key)).doubleValue()/count;}
 private LocalDateTime date(long millis){return LocalDateTime.ofInstant(Instant.ofEpochMilli(millis),metricsZone);}

	public record DailyScanMetric(LocalDateTime date, long scans, long violations,
			long durationSum, long durationCount, long sourceSizeSum, long sourceSizeCount,
			long performanceCount, long totalDurationSum, long queueDurationSum,
			long sourceDurationSum, long scannerDurationSum, long processingDurationSum,
			long scmDurationSum, long persistenceDurationSum, long cleanupDurationSum) {
		public DailyScanMetric(LocalDateTime date, long scans, long violations,
				long durationSum, long durationCount, long sourceSizeSum, long sourceSizeCount) {
			this(date, scans, violations, durationSum, durationCount, sourceSizeSum,
					sourceSizeCount, 0, 0, 0, 0, 0, 0, 0, 0, 0);
		}
	}

	public record DailyViolationMetric(LocalDateTime date, String name, long count) { }

	public record ScannerTimingMetric(LocalDateTime date, String timingsJson) { }
}
