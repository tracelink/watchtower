package com.tracelink.appsec.watchtower.core.metrics;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.test.util.ReflectionTestUtils;
import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class MetricsProjectionWriterTest {
 R1Database database;MetricsProjectionWriter writer;
 @BeforeEach void setup(){database=new R1Database();writer=database.service(new MetricsProjectionWriter(database.records,new SimpleMeterRegistry(),"UTC"));}
 @AfterEach void close(){database.close();}
 PullRequestScanEntity scan(long id){var scan=new PullRequestScanEntity();ReflectionTestUtils.setField(scan,"id",id);scan.setStartDate(1_700_000_000_000L);scan.setEndDate(1_700_000_001_000L);return scan;}
 @Test void performanceFinalizationCreatesMissingDailyProjectionRow(){
  var scan=scan(41);scan.setPerformanceComplete(true);scan.setTotalDurationMs(5000);writer.recordPrPerformance(scan);
  assertEquals(1L,database.jdbc.queryForObject("SELECT performance_count FROM metrics_scan_daily",Long.class));
  assertEquals(5000L,database.jdbc.queryForObject("SELECT total_duration_sum_ms FROM metrics_scan_daily",Long.class));
  var projections=new MetricsProjectionRepository(database.records,"UTC");assertEquals(5000.0,projections.performanceSince(0).totalMs());
 }
 @Test void recordingTheSameScanTwiceUsesAnIdempotencyMarker(){
  var scan=scan(42);writer.recordSummary("upload",scan.getId(),scan.getStartDateMillis(),scan.getEndDateMillis(),Map.of("Rule",3L),100);
  writer.recordSummary("upload",scan.getId(),scan.getStartDateMillis(),scan.getEndDateMillis(),Map.of("Rule",3L),100);
  assertEquals(1L,database.jdbc.queryForObject("SELECT scan_count FROM metrics_scan_daily",Long.class));
  assertEquals(3L,database.jdbc.queryForObject("SELECT violation_count FROM metrics_violation_daily",Long.class));
  var projections=new MetricsProjectionRepository(database.records,"UTC");assertEquals(1,projections.sum("upload","scan_count"));assertEquals(100.0,projections.average("upload","source_size_sum_bytes","source_size_count"));
 }
 @Test void nonterminalAndFailedRecordsDoNotClaimProcessingMetrics() {
  var scan=scan(45);
  for(var status:com.tracelink.appsec.watchtower.core.scan.ScanStatus.values()) {
   scan.setStatus(status);if(status==com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE)continue;
   writer.record("upload",scan,List.of());
  }
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM metrics_processed_scan",Integer.class));
  scan.setStatus(com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE);writer.record("upload",scan,List.of());
  assertEquals(1,database.jdbc.queryForObject("SELECT COUNT(*) FROM metrics_processed_scan",Integer.class));
 }
 @Test void projectionFailureRollsBackClaimAndPartialTotals(){
  var invalid=new HashMap<String,Long>();invalid.put(null,1L);
  assertThrows(RuntimeException.class,()->writer.recordSummary("upload",43,0,1000,invalid,0));
  assertEquals(0L,database.jdbc.queryForObject("SELECT COUNT(*) FROM metrics_processed_scan",Long.class));
  assertEquals(0L,database.jdbc.queryForObject("SELECT COUNT(*) FROM metrics_scan_daily",Long.class));
  writer.recordSummary("upload",43,0,1000,Map.of("fixed",1L),0);
  assertEquals(1L,database.jdbc.queryForObject("SELECT scan_count FROM metrics_scan_daily",Long.class));
 }
 @Test void theAwsWaitGrowsAScansDurationOnceAfterItWasCounted(){
  writer.recordSummary("pull_request",50,1_700_000_000_000L,1_700_000_001_000L,Map.of(),0);
  assertEquals(1000L,database.jdbc.queryForObject("SELECT duration_sum_ms FROM metrics_scan_daily",Long.class));
  writer.recordProviderWait(50,1_700_000_001_000L,60_000L,true);
  writer.recordProviderWait(50,1_700_000_001_000L,60_000L,true);
  assertEquals(61_000L,database.jdbc.queryForObject("SELECT duration_sum_ms FROM metrics_scan_daily",Long.class),"added once, by the marker");
  assertEquals(60_000L,database.jdbc.queryForObject("SELECT total_duration_sum_ms FROM metrics_scan_daily",Long.class));
  assertEquals(60_000L,database.jdbc.queryForObject("SELECT scanner_duration_sum_ms FROM metrics_scan_daily",Long.class));
  assertEquals(1L,database.jdbc.queryForObject("SELECT duration_count FROM metrics_scan_daily",Long.class),"the scan is still one scan");
 }
 @Test void theAwsWaitLeavesTheSpeedBreakdownAloneWhenTheScanHadNoTimings(){
  writer.recordSummary("pull_request",51,1_700_000_000_000L,1_700_000_001_000L,Map.of(),0);
  writer.recordProviderWait(51,1_700_000_001_000L,30_000L,false);
  assertEquals(31_000L,database.jdbc.queryForObject("SELECT duration_sum_ms FROM metrics_scan_daily",Long.class));
  assertEquals(0L,database.jdbc.queryForObject("SELECT total_duration_sum_ms FROM metrics_scan_daily",Long.class));
 }
 @Test void aWaitForAScanThatWasNeverCountedOrHadNoWaitChangesNothing(){
  writer.recordProviderWait(52,1_700_000_001_000L,60_000L,true);
  assertEquals(0L,database.jdbc.queryForObject("SELECT COUNT(*) FROM metrics_scan_daily",Long.class));
  writer.recordSummary("pull_request",53,1_700_000_000_000L,1_700_000_001_000L,Map.of(),0);
  writer.recordProviderWait(53,1_700_000_001_000L,0L,true);
  assertEquals(1000L,database.jdbc.queryForObject("SELECT duration_sum_ms FROM metrics_scan_daily",Long.class));
 }
}
