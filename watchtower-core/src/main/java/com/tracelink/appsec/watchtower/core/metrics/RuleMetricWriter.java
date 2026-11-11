package com.tracelink.appsec.watchtower.core.metrics;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import com.tracelink.appsec.watchtower.core.persistence.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;

import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;

/** Contributions include informational findings and unknown coverage; reused reports add none. */
@Service
public class RuleMetricWriter {
 private final LedgerRepository records;
 public RuleMetricWriter(LedgerRepository records) { this.records=records; }
 @Transactional(propagation=Propagation.REQUIRES_NEW)
 public void markProcessed(String type,long id) {
  records.lockScope("rule-metrics");
  if(records.find(RuleMetricProcessedEntity.class,new RuleMetricProcessedEntity.Id(type,id))==null)records.insert(new RuleMetricProcessedEntity(type,id));
 }
 public record Count(RuleExecutionIdentity identity, Boolean blocking) { }
 public record Totals(RuleExecutionIdentity identity,long findings,long blocking,long blockingUnknown) { }
 public static List<Totals> totals(List<Count> findings) {
  Map<String,List<Count>> groups=new LinkedHashMap<>();findings.forEach(f->groups.computeIfAbsent(key(f.identity(),"unknown"),k->new ArrayList<>()).add(f));
  return groups.values().stream().map(fs->new Totals(fs.getFirst().identity(),fs.size(),fs.stream().filter(f->Boolean.TRUE.equals(f.blocking())).count(),fs.stream().filter(f->f.blocking()==null).count())).toList();
 }
 public static String key(RuleExecutionIdentity i, String fallback) {
  return RuleRevision.definition("metric-identity", "v1")
   .field("id",i==null||i.ruleId()==null?null:i.ruleId().toString())
   .field("ruleModule",i==null?null:i.module()).field("revision",i==null?null:i.revision())
   .field("external",i==null?null:i.externalRuleKey()).field("origin",i==null?fallback:i.originKey()).hash();
 }
 @Transactional(propagation=Propagation.REQUIRES_NEW)
 public void record(String type,long id,long end,CodeScanExecutionSnapshot snapshot,List<Count> findings) { recordTotals(type,id,end,snapshot,totals(findings)); }
 @Transactional(propagation=Propagation.REQUIRES_NEW)
 public void recordTotals(String type,long id,long end,CodeScanExecutionSnapshot snapshot,List<Totals> totals) {
  records.lockScope("rule-metrics");
  var processed=new RuleMetricProcessedEntity.Id(type,id);
  if(records.find(RuleMetricProcessedEntity.class,processed)!=null)return;
  records.insert(new RuleMetricProcessedEntity(type,id));
  if(snapshot!=null && snapshot.reusedFromScanId()!=null) return;
  Map<String,Totals> grouped=new LinkedHashMap<>();totals.forEach(f->grouped.put(key(f.identity(),"unknown"),f));
  Map<String,CodeScanExecutionSnapshot.SelectedRule> selected=new HashMap<>();
  if(snapshot!=null) snapshot.rules().forEach(r->{String k=key(r.identity(),"unknown");selected.put(k,r);grouped.putIfAbsent(k,new Totals(r.identity(),0,0,0));});
  long bucket=Instant.ofEpochMilli(end).atZone(ZoneOffset.UTC).toLocalDate().atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
  grouped.forEach((k,total)->{
   var r=selected.get(k);var i=total.identity();String coverage=r==null?"UNKNOWN":r.coverage();
   if(r!=null&&snapshot.engines().stream().anyMatch(e->Objects.equals(e.scanner(),r.scanner())&&"FAILED".equals(e.status()))) coverage="FAILED";
   Long opportunities=r==null?null:r.evaluatedOpportunities();
   var contribution=new RuleMetricScanEntity(type,id,k,i==null?null:i.ruleId(),i==null?null:i.revision(),i==null?null:i.module(),bucket,total.findings(),total.blocking(),total.blockingUnknown(),opportunities,coverage,total.findings()==0?null:end);
   var engines=r==null||r.scanner()==null?List.<CodeScanExecutionSnapshot.EngineExecution>of():snapshot.engines().stream().filter(e->r.scanner().equals(e.scanner())).toList();
   if(engines.size()==1&&Set.of("RAN","FAILED","SKIPPED","DISABLED","UNSUPPORTED","NOT_APPLICABLE").contains(Objects.toString(engines.getFirst().status(),"")))contribution.engineStatus=engines.getFirst().status();
   records.insert(contribution);
   var daily=records.find(RuleMetricDailyEntity.class,new RuleMetricDailyEntity.Id(type,bucket,k));
   if(daily==null)records.insert(new RuleMetricDailyEntity(type,bucket,k,i==null?null:i.ruleId(),i==null?null:i.revision(),total.findings(),total.blocking(),total.blockingUnknown(),1L));
   else {daily.findings+=total.findings();daily.blocking+=total.blocking();daily.blockingUnknown+=total.blockingUnknown();daily.scans++;}
  });
 }
 @Transactional(propagation=Propagation.REQUIRES_NEW)
 public void recordEntities(String type,long id,long end,CodeScanExecutionSnapshot snapshot,List<? extends AbstractCodeScanViolationEntity<?>> fs) {
  record(type,id,end,snapshot,fs.stream().map(f->new Count(f.getRuleIdentity(),f.getEffectiveBlocking())).toList());
 }
 @Transactional(propagation=Propagation.REQUIRES_NEW)
 public void recordRepository(long id,long end,CodeScanExecutionSnapshot snapshot,List<RepoScanReport.Finding> fs) {
  record("repository",id,end,snapshot,fs.stream().map(f->new Count(f.ruleIdentity(),f.effectiveBlocking())).toList());
 }
}
