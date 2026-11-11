package com.tracelink.appsec.watchtower.core.feedback;

import java.util.*;
import com.tracelink.appsec.watchtower.core.scan.code.AbstractCodeScanViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.*;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.persistence.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.AssistantText;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;

/** Immutable occurrences are resolved by the server, never supplied rule ids or current names. */
@Service
public class FindingFeedbackService {
 @org.springframework.beans.factory.annotation.Autowired(required=false)
 private com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService remoteAssessments;
 public enum Judgment { TRUE_POSITIVE, FALSE_POSITIVE, UNKNOWN }
 public enum Disposition { ACTION_REQUIRED, ACCEPTED_RISK, TEST_CODE, NOT_EXPLOITABLE, OTHER }
 public record Update(String scanType,long scanId,List<String> findingKeys,Judgment judgment,
   Disposition disposition,String explanation,Map<String,Long> versions) { }
 public record Occurrence(Long ruleId,String revision,Boolean blocking,long occurredAt) { }
 private final LedgerRepository records;
 private final RepoScanRepository repositories;
 private final RepoScanReportService reports;
 public FindingFeedbackService(LedgerRepository records,RepoScanRepository repositories,RepoScanReportService reports) {
  this.records=records;this.repositories=repositories;this.reports=reports;
 }
 public static String occurrenceKey(String type,long scanId,String key) {
  return RuleRevision.definition("finding-occurrence","v1").field("type",type)
    .field("scan",Long.toString(scanId)).field("finding",key).hash();
 }
 @Transactional(readOnly=true)
 public Occurrence resolve(String type,long scanId,String key) {
  if(scanId<=0||key==null||key.length()>64) throw new IllegalArgumentException("Invalid finding reference");
  if(remoteAssessments!=null && key.matches("[a-f0-9]{64}")) {
   var remote=remoteAssessments.occurrence(type,scanId,key); if(remote.isPresent()) return remote.get();
  }
  if("repository".equals(type)) {
   var scan=repositories.findById(scanId).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND));
   var report=reports.getReport(scan).orElseThrow(()->new ResponseStatusException(HttpStatus.GONE,"Report unavailable"));
   var f=report.findings().stream().filter(x->key.equals(x.findingKey())).findFirst()
     .orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Unknown finding"));
   var i=f.ruleIdentity();return new Occurrence(i==null?null:i.ruleId(),i==null?null:i.revision(),f.effectiveBlocking(),scan.getEndDate());
  }
  long findingId;
  try {findingId=Long.parseLong(key);}catch(NumberFormatException e){throw new IllegalArgumentException("Invalid finding id");}
  AbstractCodeScanViolationEntity<?> finding=switch(type) {
   case "pull_request" -> records.find(PullRequestViolationEntity.class,findingId);
   case "upload" -> records.find(UploadViolationEntity.class,findingId);
   default -> throw new IllegalArgumentException("Unsupported scan type");
  };
  if(finding==null||finding.getScan().getId()!=scanId)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Unknown finding");
  return new Occurrence(finding.getExecutionRuleId(),finding.getRuleRevision(),finding.getEffectiveBlocking(),finding.getScan().getEndDateMillis());
 }
 @Transactional
 public void save(Update update,String reviewer) {
  if(update.findingKeys()==null||update.findingKeys().isEmpty()||update.findingKeys().size()>100||
    update.judgment()==null||update.disposition()==null||update.versions()==null) throw new IllegalArgumentException("Select 1–100 findings and a judgment");
  if(new HashSet<>(update.findingKeys()).size()!=update.findingKeys().size()) throw new IllegalArgumentException("Duplicate findings");
  String note=AssistantText.bounded(update.explanation(),300);long now=System.currentTimeMillis();
  // A saved scan row exists before feedback; its lock also serializes first-time feedback creation.
  switch(update.scanType()) {
   case "pull_request" -> records.lock(PullRequestScanEntity.class,update.scanId());
   case "upload" -> records.lock(UploadScanEntity.class,update.scanId());
   case "repository" -> records.lock(RepoScanEntity.class,update.scanId());
   default -> throw new IllegalArgumentException("Unsupported scan type");
  }
  for(String key:update.findingKeys()) {
   Occurrence o=resolve(update.scanType(),update.scanId(),key);String occurrence=occurrenceKey(update.scanType(),update.scanId(),key);
   long expected=update.versions().getOrDefault(key,0L);
   if(expected==0) {
    if(records.find(FindingFeedbackEntity.class,occurrence)!=null)throw new ResponseStatusException(HttpStatus.CONFLICT,"Feedback changed; reload");
    records.insert(new FindingFeedbackEntity(occurrence,update.scanType(),update.scanId(),key,o.ruleId(),o.revision(),o.blocking(),o.occurredAt(),update.judgment().name(),update.disposition().name(),note,reviewer,now,1L));
   } else if(records.update("UPDATE FindingFeedbackEntity SET judgment=?1,disposition=?2,explanation=?3,reviewer=?4,updatedAt=?5,version=version+1 WHERE occurrenceKey=?6 AND version=?7" ,update.judgment().name(),update.disposition().name(),note,reviewer,now,occurrence,expected)!=1) throw new ResponseStatusException(HttpStatus.CONFLICT,"Feedback changed; reload");
   records.insert(new FindingFeedbackAuditEntity(null,occurrence,update.judgment().name(),update.disposition().name(),note,reviewer,now));
  }
 }
 public List<Map<String,Object>> forScan(String type,long id) {
  return records.maps("SELECT findingKey AS finding_key,judgment AS judgment,disposition AS disposition,explanation AS explanation,reviewer AS reviewer,updatedAt AS updated_at,version AS version FROM FindingFeedbackEntity WHERE scanType=?1 AND scanId=?2 ORDER BY findingKey",0,20000 ,type,id);
 }
 /** The latest judgment of each reviewed finding of one scan, by finding key. */
 public Map<String,String> judgmentsByKey(String type,long id) {
  Map<String,String> judgments=new java.util.HashMap<>();
  forScan(type,id).forEach(row->judgments.put(String.valueOf(row.get("finding_key")),String.valueOf(row.get("judgment"))));
  return judgments;
 }
 public List<Map<String,Object>> audit(String type,long scanId,String key) {
  resolve(type,scanId,key);
  return records.maps("SELECT judgment AS judgment,disposition AS disposition,explanation AS explanation,reviewer AS reviewer,changedAt AS changed_at FROM FindingFeedbackAuditEntity WHERE occurrenceKey=?1 ORDER BY auditId DESC",0,20 ,occurrenceKey(type,scanId,key));
 }
}
