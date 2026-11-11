package com.tracelink.appsec.watchtower.web;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.jdbc.core.JdbcTemplate;
import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionWriter;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

/** Exercises the real Flyway schema, avoiding Hibernate-generated H2 fixture constraints. */
@SpringBootTest(properties={"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
 "spring.datasource.url=jdbc:h2:mem:uat-metrics;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@ActiveProfiles("dev")
class MetricsReconciliationTest {
 @MockitoBean com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
 @Autowired JdbcTemplate jdbc;@Autowired LedgerRepository records;@Autowired MetricsProjectionWriter writer;
 @Autowired org.springframework.transaction.PlatformTransactionManager transactions;
 @BeforeEach void clean() {
  for(String table:List.of("metrics_processed_scan","metrics_violation_daily","metrics_scan_daily","pull_request_violations","pull_request_scans","pull_request_container"))jdbc.update("DELETE FROM "+table);
 }
 void seedPr(long id,long end) {
  jdbc.update("INSERT INTO pull_request_container(container_id,last_review_date,resolved,api_label,author,source_branch) VALUES (?,0,FALSE,'uat','fixture','main')",id);
  jdbc.update("INSERT INTO pull_request_scans(scan_entity_id,container_id,submit_date,start_date,end_date,status,blocked,source_size_bytes,total_duration_ms,queue_wait_duration_ms,source_preparation_duration_ms,scanner_execution_duration_ms,result_processing_duration_ms,scm_reporting_duration_ms,persistence_duration_ms,cleanup_duration_ms,performance_complete,changed_file_count) VALUES (?,?,0,0,?,'Done',FALSE,0,0,0,0,0,0,0,0,0,FALSE,0)",id,id,end);
 }
 @Test void dryRunAndRepairRebuildOnlySuccessfulProcessingAndRemainIdempotent() {
  for(int id=1;id<=4;id++) {
   seedPr(id,id==3?0:1700000001000L);
   var saved=records.find(PullRequestScanEntity.class,(long)id);saved.setStatus(id==1?com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE:id==2?com.tracelink.appsec.watchtower.core.scan.ScanStatus.FAILED:id==3?com.tracelink.appsec.watchtower.core.scan.ScanStatus.IN_PROGRESS:com.tracelink.appsec.watchtower.core.scan.ScanStatus.NOT_STARTED);records.save(saved);
   writer.recordSummary("pull_request",id,1700000000000L,1700000001000L,Map.of("historical",1L),0);
  }
  var type=MetricsProjectionWriter.ReconcileType.PULL_REQUEST;
  var dry=writer.reconcile(type,null);
  assertEquals(4,dry.projectedProcessing());assertEquals(1,dry.successfulProcessing());assertFalse(dry.repaired());
  assertEquals(4,jdbc.queryForObject("SELECT COUNT(*) FROM metrics_processed_scan",Integer.class));
  var fixed=writer.reconcile(type,dry.fingerprint());assertTrue(fixed.repaired());
  assertEquals(1,jdbc.queryForObject("SELECT SUM(scan_count) FROM metrics_scan_daily",Integer.class));
  assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM metrics_violation_daily",Integer.class));
  assertEquals(4,jdbc.queryForObject("SELECT COUNT(*) FROM pull_request_scans",Integer.class));
  var repeat=writer.reconcile(type,null);writer.reconcile(type,repeat.fingerprint());
  assertEquals(1,jdbc.queryForObject("SELECT SUM(scan_count) FROM metrics_scan_daily",Integer.class));
  writer.recordSummary("pull_request",1,1700000000000L,1700000001000L,Map.of(),0);
  assertEquals(1,jdbc.queryForObject("SELECT SUM(scan_count) FROM metrics_scan_daily",Integer.class));
 }
 @Test void concurrentPersistenceInvalidatesDryRunAndExpiredSourceBlocksRepair() {
  seedPr(1,1700000001000L);var saved=records.find(PullRequestScanEntity.class,1L);saved.setStatus(com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE);records.save(saved);
  var type=MetricsProjectionWriter.ReconcileType.PULL_REQUEST;var before=writer.reconcile(type,null);
  writer.recordSummary("pull_request",1,1700000000000L,1700000001000L,Map.of(),0);
  assertThrows(IllegalStateException.class,()->writer.reconcile(type,before.fingerprint()));
  writer.recordSummary("pull_request",999,1700000000000L,1700000001000L,Map.of(),0);
  var expired=writer.reconcile(type,null);assertEquals(1,expired.orphanedMarkers());
  assertThrows(IllegalStateException.class,()->writer.reconcile(type,expired.fingerprint()));
  assertEquals(2,jdbc.queryForObject("SELECT SUM(scan_count) FROM metrics_scan_daily",Integer.class));
 }
 @Test void repairAndResultPersistenceSerializeOnTheSameLockWithoutDoubleCounting() throws Exception {
  seedPr(1,1700000001000L);
  var type=MetricsProjectionWriter.ReconcileType.PULL_REQUEST;
  var dry=writer.reconcile(type,null);
  var repaired=new java.util.concurrent.CountDownLatch(1);
  var allowCommit=new java.util.concurrent.CountDownLatch(1);
  var recording=new java.util.concurrent.CountDownLatch(1);
  try(var executor=java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
   var repair=executor.submit(()->new org.springframework.transaction.support.TransactionTemplate(transactions).execute(status->{
    writer.reconcile(type,dry.fingerprint());repaired.countDown();
    try { if(!allowCommit.await(10,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("Commit was not released"); }
    catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IllegalStateException(interrupted);}
    return null;
   }));
   try {
    assertTrue(repaired.await(10,java.util.concurrent.TimeUnit.SECONDS));
    var ordinary=executor.submit(()->{recording.countDown();writer.recordSummary("pull_request",1,0,1700000001000L,Map.of(),0);});
    assertTrue(recording.await(10,java.util.concurrent.TimeUnit.SECONDS));
    assertThrows(java.util.concurrent.TimeoutException.class,()->ordinary.get(150,java.util.concurrent.TimeUnit.MILLISECONDS));
    allowCommit.countDown();
    repair.get(10,java.util.concurrent.TimeUnit.SECONDS);ordinary.get(10,java.util.concurrent.TimeUnit.SECONDS);
   } finally {allowCommit.countDown();}
  }
  assertEquals(1,jdbc.queryForObject("SELECT SUM(scan_count) FROM metrics_scan_daily",Integer.class));
  assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM metrics_processed_scan WHERE metric_kind='result'",Integer.class));
 }
}
