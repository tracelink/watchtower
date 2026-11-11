package com.tracelink.appsec.watchtower.core.rule;

import java.util.*;
import com.tracelink.appsec.watchtower.core.persistence.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import com.tracelink.appsec.watchtower.core.assistant.AssistantText;

@Service
public class RuleReviewService {
 public enum Status { OPEN, IN_REVIEW, ACCEPTED, REJECTED, CLOSED }
 public record Review(String id,long ruleId,String revision,String owner,Status status,String reason,
   String recommendation,String evidenceType,String evidenceId,String sessionId,String turnId,String outcome,long version) { }
 public record Case(long ruleId,String revision,String kind,String fixtureRef,String fixtureHash,
   String expectedBehavior,String engine,String language) { }
 private final LedgerRepository records;private final RuleService rules;
 public RuleReviewService(LedgerRepository records,RuleService rules){this.records=records;this.rules=rules;}
 @Transactional
 public String save(Review r,String actor) {
  if(r.status()==null||r.ruleId()<=0) throw new IllegalArgumentException("Invalid review");
  String owner=AssistantText.bounded(r.owner(),255),reason=AssistantText.bounded(r.reason(),64);
  String summary=AssistantText.bounded(r.recommendation(),300),outcome=AssistantText.bounded(r.outcome(),300);
  if(owner.isBlank()||reason.isBlank()) throw new IllegalArgumentException("Owner and reason required");
  if(r.evidenceType()!=null&&!Set.of("finding","scan","revision","case").contains(r.evidenceType())) throw new IllegalArgumentException("Invalid evidence type");
  if(r.evidenceId()!=null&&!r.evidenceId().matches("[A-Za-z0-9:_-]{1,64}")) throw new IllegalArgumentException("Invalid evidence reference");
  long now=System.currentTimeMillis();String id=r.id();
  if(id==null) {
   records.lock(RuleEntity.class,r.ruleId());var rule=current(r.ruleId());if(!Objects.equals(rule.getRevision(),r.revision()))throw new ResponseStatusException(HttpStatus.CONFLICT,"Rule changed; reload");
   validateEvidence(r);
   id=UUID.randomUUID().toString();
   records.insert(new RuleReviewItemEntity(id,r.ruleId(),r.revision(),owner,r.status().name(),reason,summary,r.evidenceType(),r.evidenceId(),uuid(r.sessionId()),uuid(r.turnId()),outcome,now,now,1L));
  } else {
   uuid(id);
   if(records.update("UPDATE RuleReviewItemEntity SET owner=?1,status=?2,reason=?3,recommendation=?4,outcome=?5,updatedAt=?6,version=version+1 WHERE reviewId=?7 AND ruleId=?8 AND version=?9",
     owner,r.status().name(),reason,summary,outcome,now,id,r.ruleId(),r.version())!=1)throw new ResponseStatusException(HttpStatus.CONFLICT,"Review changed; reload");
  }
  records.insert(new RuleReviewAuditEntity(null,id,r.status().name(),actor,outcome,now));return id;
 }
 private void validateEvidence(Review r) {
  if(r.evidenceType()==null&&r.evidenceId()==null)return;
  if(r.evidenceType()==null||r.evidenceId()==null)throw new IllegalArgumentException("Select an evidence record");
  String suffix=r.revision()==null?" AND e.revision IS NULL":" AND e.revision=?3";
  Object[] args=r.revision()==null?new Object[]{r.ruleId(),r.evidenceId()}:new Object[]{r.ruleId(),r.evidenceId(),r.revision()};
  boolean valid=switch(r.evidenceType()) {
   case "revision" -> Objects.equals(r.revision(),r.evidenceId());
   case "case" -> records.scalar(Long.class,"SELECT COUNT(e) FROM RuleRegressionCaseEntity e WHERE e.ruleId=?1 AND e.caseId=?2"+suffix,args)>0;
   case "finding" -> {
    if(r.evidenceId().matches("[0-9]+")) {
     // Retain the legacy PR reference contract; new selectors use the unambiguous occurrence key.
     Object[] legacy=r.revision()==null?new Object[]{r.ruleId(),Long.parseLong(r.evidenceId())}:new Object[]{r.ruleId(),Long.parseLong(r.evidenceId()),r.revision()};
     yield records.scalar(Long.class,"SELECT COUNT(e) FROM PullRequestViolationEntity e WHERE e.ruleIdentity.ruleId=?1 AND e.id=?2"+suffix.replace("e.revision","e.ruleIdentity.revision"),legacy)>0;
    }
    yield records.scalar(Long.class,"SELECT COUNT(e) FROM FindingFeedbackEntity e WHERE e.ruleId=?1 AND e.occurrenceKey=?2"+suffix,args)>0;
   }
   case "scan" -> {
    String[] parts=r.evidenceId().split(":",-1);
    if(parts.length!=2||!Set.of("pull_request","upload","repository").contains(parts[0])||!parts[1].matches("[0-9]+"))yield false;
    Object[] scanArgs=r.revision()==null?new Object[]{r.ruleId(),parts[0],Long.parseLong(parts[1])}:new Object[]{r.ruleId(),parts[0],Long.parseLong(parts[1]),r.revision()};
    yield records.scalar(Long.class,"SELECT COUNT(e) FROM RuleMetricScanEntity e WHERE e.ruleId=?1 AND e.scanType=?2 AND e.scanId=?3"+(r.revision()==null?" AND e.revision IS NULL":" AND e.revision=?4"),scanArgs)>0;
   }
   default -> false;
  };
  if(!valid)throw new IllegalArgumentException("Evidence is not available for this rule revision");
 }
 public RuleDto current(long id){try{return rules.getCurrentRule(id).toDto();}catch(Exception e){throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Unknown rule");}}
 private String uuid(String value){if(value==null)return null;return UUID.fromString(value).toString();}
 public List<Map<String,Object>> list(long ruleId,int offset){if(offset<0||offset>10000)throw new IllegalArgumentException("Invalid page");return records.maps("SELECT r FROM RuleReviewItemEntity r WHERE r.ruleId=?1 ORDER BY r.updatedAt DESC,r.reviewId",offset,20,ruleId);}
 public List<Map<String,Object>> audit(String id){return records.maps("SELECT r.status AS status,r.actor AS actor,r.outcome AS outcome,r.changedAt AS changed_at FROM RuleReviewAuditEntity r WHERE r.reviewId=?1 ORDER BY r.auditId DESC",0,20,uuid(id));}
 @Transactional
 public String intake(Case c,String reviewer){
  records.lock(RuleEntity.class,c.ruleId());var rule=current(c.ruleId());if(!Objects.equals(rule.getRevision(),c.revision()))throw new ResponseStatusException(HttpStatus.CONFLICT,"Rule changed; reload");
  if(!Set.of("FALSE_POSITIVE","MISSED_VULNERABILITY").contains(c.kind())||!Set.of("MATCH","NO_MATCH").contains(c.expectedBehavior()))throw new IllegalArgumentException("Invalid case");
  if(c.fixtureRef()==null||!c.fixtureRef().matches("[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")||c.fixtureRef().contains("..")||c.fixtureHash()==null||!c.fixtureHash().matches("[a-f0-9]{64}"))throw new IllegalArgumentException("Use a reviewed versioned fixture reference and SHA-256, without source or secrets");
  String id=UUID.randomUUID().toString();records.insert(new RuleRegressionCaseEntity(id,c.ruleId(),c.revision(),c.kind(),c.fixtureRef(),c.fixtureHash(),c.expectedBehavior(),AssistantText.bounded(c.engine(),64),AssistantText.bounded(c.language(),64),reviewer,System.currentTimeMillis()));return id;
 }
}
