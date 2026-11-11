package com.tracelink.appsec.watchtower.core.metrics;

import java.util.*;
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.annotation.Transactional;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.assistant.AssistantState;

/** Bounded reconciliation uses saved metadata only; no source downloads or provider calls. */
@Component
public class RuleEvidenceMaintenance {
 private final LedgerRepository records;private final RuleMetricWriter writer;private final RuleHealthService health;private final RepoScanReportService reports;private final TransactionTemplate transaction;
 public RuleEvidenceMaintenance(LedgerRepository records,RuleMetricWriter writer,RuleHealthService health,RepoScanRepository repos,RepoScanReportService reports,PlatformTransactionManager tm){this.records=records;this.writer=writer;this.health=health;this.reports=reports;this.transaction=new TransactionTemplate(tm);}
 @Scheduled(fixedDelayString="${watchtower.rule-health.reconcile-delay-ms:60000}")
 @SchedulerLock(name="ruleEvidenceReconciliation",lockAtMostFor="PT5M")
 @Transactional(readOnly=true)
 public void reconcile(){
  String unseen="NOT EXISTS (SELECT p.scanId FROM RuleMetricProcessedEntity p WHERE p.scanType=?1 AND p.scanId=s.id)";
  for(var scan:records.list(PullRequestScanEntity.class,"SELECT s FROM PullRequestScanEntity s WHERE s.endDate>0 AND s.executionSnapshotJson IS NOT NULL AND "+unseen+" ORDER BY s.id",0,100,"pull_request"))
   writer.recordEntities("pull_request",scan.getId(),scan.getEndDateMillis(),CodeScanExecutionSnapshotCodec.decode(scan.getExecutionSnapshotJson()),scan.getViolations());
  for(var scan:records.list(UploadScanEntity.class,"SELECT s FROM UploadScanEntity s WHERE s.endDate>0 AND s.executionSnapshotJson IS NOT NULL AND "+unseen+" ORDER BY s.id",0,100,"upload"))
   writer.recordEntities("upload",scan.getId(),scan.getEndDateMillis(),CodeScanExecutionSnapshotCodec.decode(scan.getExecutionSnapshotJson()),scan.getViolations());
  for(var scan:records.list(RepoScanEntity.class,"SELECT s FROM RepoScanEntity s WHERE s.endDate>0 AND s.reportKey IS NOT NULL AND s.executionSnapshotJson IS NOT NULL AND "+unseen+" ORDER BY s.id",0,100,"repository"))
   reports.getReport(scan).ifPresent(report->{if(report.executionSnapshot()!=null&&(report.executionSnapshot().reusedFromScanId()!=null||report.identityCounts()!=null))writer.recordTotals("repository",scan.getId(),scan.getEndDate(),report.executionSnapshot(),report.identityCounts()==null?List.of():report.identityCounts());else writer.markProcessed("repository",scan.getId());});
 }
 @Scheduled(fixedDelayString="${watchtower.rule-health.rollup-delay-ms:60000}")
 @SchedulerLock(name="ruleHealthRollup",lockAtMostFor="PT10M")
 public void rollup(){
  // Hibernate set operations retain the original bounded union of current and observed revisions.
  var keys=records.maps("SELECT candidates.rule_id AS rule_id,candidates.rule_revision AS rule_revision FROM (SELECT r.id AS rule_id,r.stewardship.revision AS rule_revision FROM RuleEntity r UNION SELECT m.ruleId AS rule_id,m.revision AS rule_revision FROM RuleMetricScanEntity m WHERE m.ruleId IS NOT NULL UNION SELECT f.ruleId AS rule_id,f.revision AS rule_revision FROM FindingFeedbackEntity f WHERE f.ruleId IS NOT NULL) candidates LEFT JOIN RuleHealthEntity h ON h.ruleId=candidates.rule_id AND h.revisionKey=COALESCE(candidates.rule_revision,'unknown') WHERE h.computedAt IS NULL OR h.computedAt<?1 ORDER BY COALESCE(h.computedAt,0),candidates.rule_id",0,100,System.currentTimeMillis()-3600000);
  for(var key:keys){
   long id=((Number)key.get("rule_id")).longValue();String revision=(String)key.get("rule_revision");
   var facts=new LinkedHashMap<String,Object>();facts.put("30d",health.health(id,revision,30,"all"));facts.put("90d",health.health(id,revision,90,"all"));
   try{String json=AssistantState.mapper().writeValueAsString(facts);transaction.executeWithoutResult(tx->{records.lockScope("rule-health");records.save(new RuleHealthEntity(id,revision==null?"unknown":revision,System.currentTimeMillis(),json));});}
   catch(com.fasterxml.jackson.core.JsonProcessingException e){throw new IllegalStateException("Health serialization failed");}
  }
 }
}
