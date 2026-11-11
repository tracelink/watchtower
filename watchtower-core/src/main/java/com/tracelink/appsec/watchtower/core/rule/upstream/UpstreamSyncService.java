package com.tracelink.appsec.watchtower.core.rule.upstream;

import java.util.*;
import java.util.function.Consumer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleCandidateService;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory;

/**
 * R5.4 upstream sync. Modules re-import their provided catalogs at startup (unchanged behavior);
 * once the application is ready this compares each module's provided rules with the last snapshot.
 * The first sync of a module only records a baseline. Later differences become an update record:
 * newly added rules are held (they run and report, but never block) until a person approves them,
 * and changed rules with reviewed fixtures are re-tested in the background. Deterministic.
 */
@Service
public class UpstreamSyncService {
 private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(UpstreamSyncService.class);
 private static final String LOCK="upstream-sync";
 static final int MAX_SNAPSHOT=100_000,LISTED=20;
 private final LedgerRepository records;private final RuleService rules;private final RuleCandidateService candidates;
 // Lazy: AsyncJobService collects every job handler, including this service's own job.
 private final ObjectProvider<AsyncJobService> jobs;private final TransactionTemplate separate,required;
 public UpstreamSyncService(LedgerRepository records,RuleService rules,RuleCandidateService candidates,ObjectProvider<AsyncJobService> jobs,PlatformTransactionManager transactions){
  this.records=records;this.rules=rules;this.candidates=candidates;this.jobs=jobs;
  separate=new TransactionTemplate(transactions);separate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
  required=new TransactionTemplate(transactions);
 }
 @EventListener(ApplicationReadyEvent.class)
 public void onReady(){
  // Event listeners are invoked on the target, not the proxy: start the transaction explicitly so the
  // cross-pod lock, the all-or-nothing writes and the after-commit job really apply.
  try{required.execute(status->compare());}catch(RuntimeException e){LOG.warn("Upstream rule sync failed; it will run again on the next start",e);}
 }
 /** Returns the ids of new update records. Serialized across pods; a second pod finds no difference. */
 @Transactional
 public List<String> sync(){return compare();}
 /**
  * Known windows, by design: a rule imported at startup can block on another pod until this pod is
  * ready and other pods' rule caches refresh (up to their TTL); a rule whose revision cannot be
  * computed (null) is never reported as changed.
  */
 private List<String> compare(){
  records.lockScope(LOCK);
  // Names are compared case-insensitively, as the import and MySQL's collation treat them.
  Map<String,Map<String,RuleDto>> current=new TreeMap<>();
  for(var rule:rules.getRules())if(rule.isProvided()&&!rule.isRetired()&&rule.getId()!=null)current.computeIfAbsent(rule.getModule(),m->new TreeMap<>()).put(key(rule.getName()),rule);
  // A module that now provides no rules still has its removals recorded.
  for(var m:records.maps("SELECT DISTINCT s.key.module AS module FROM UpstreamRuleSnapshotEntity s",0,1000))current.putIfAbsent((String)m.get("module"),new TreeMap<>());
  List<String> created=new ArrayList<>();List<String> toCheck=new ArrayList<>();long now=System.currentTimeMillis();
  for(var module:current.entrySet()){
   var previous=new HashMap<String,UpstreamRuleSnapshotEntity>();
   for(var s:records.list(UpstreamRuleSnapshotEntity.class,"SELECT s FROM UpstreamRuleSnapshotEntity s WHERE s.key.module=?1",0,MAX_SNAPSHOT,module.getKey()))previous.put(key(s.getKey().getRuleName()),s);
   var rulesNow=module.getValue();
   if(previous.isEmpty()){if(!rulesNow.isEmpty())snapshot(module.getKey(),rulesNow);continue;}
   List<Map<String,Object>> added=new ArrayList<>(),changed=new ArrayList<>();List<String> removed=new ArrayList<>();
   rulesNow.forEach((name,rule)->{var before=previous.get(name);
    if(before==null)added.add(Map.of("rule_id",rule.getId(),"name",rule.getName()));
    else if(!Objects.equals(before.getRevision(),rule.getRevision()))changed.add(Map.of("rule_id",rule.getId(),"name",rule.getName()));});
   previous.entrySet().stream().filter(e->!rulesNow.containsKey(e.getKey())).map(e->e.getValue().getKey().getRuleName()).sorted().forEach(removed::add);
   if(added.isEmpty()&&changed.isEmpty()&&removed.isEmpty())continue;
   var heldIds=added.stream().map(a->((Number)a.get("rule_id")).longValue()).toList();
   int held=heldIds.isEmpty()?0:records.update("UPDATE RuleEntity r SET r.stewardship.upstreamHoldSince=?1,r.persistenceVersion=r.persistenceVersion+1 WHERE r.id IN ?2 AND r.stewardship.upstreamHoldSince IS NULL",now,heldIds);
   String id=UUID.randomUUID().toString();
   records.insert(new UpstreamUpdateEntity(id,module.getKey(),now,RuleDefinitionHistory.encode(added),RuleDefinitionHistory.encode(changed),RuleDefinitionHistory.encode(removed),held,changed.isEmpty()?"NOT_NEEDED":"QUEUED"));
   records.update("DELETE FROM UpstreamRuleSnapshotEntity s WHERE s.key.module=?1",module.getKey());
   snapshot(module.getKey(),rulesNow);
   created.add(id);if(!changed.isEmpty())toCheck.add(id);
   LOG.info("Upstream update for {}: {} added (held {}), {} changed, {} removed",module.getKey(),added.size(),held,changed.size(),removed.size());
  }
  if(!created.isEmpty())TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){@Override public void afterCommit(){
   rules.invalidateRuleCache();
   for(String id:toCheck){
    try{separate.executeWithoutResult(tx->{if(jobs.getObject().enqueue(AsyncJobType.UPSTREAM_CHECK,id,"upstream-check:"+id,"system").isEmpty())setCheck(id,"UNAVAILABLE",null);});}
    catch(RuntimeException e){LOG.warn("Upstream check {} could not be queued",id,e);setCheck(id,"UNAVAILABLE",null);}
   }
  }});
  return created;
 }
 private static String key(String name){return name==null?"":name.toLowerCase(Locale.ROOT);}
 private void snapshot(String module,Map<String,RuleDto> rulesNow){
  rulesNow.values().forEach(rule->records.insert(new UpstreamRuleSnapshotEntity(module,rule.getName(),rule.getId(),rule.getRevision())));
 }
 /** Background job: re-tests changed rules that have reviewed fixtures. Human labels decide. */
 public void check(String updateId,Consumer<String> progress){
  var update=records.find(UpstreamUpdateEntity.class,updateId);
  if(update==null||!"QUEUED".equals(update.getCheckStatus()))return;
  List<Map<String,Object>> results=new ArrayList<>();var changed=decode(update.getChangedJson());
  for(int i=0;i<changed.size();i++){
   progress.accept("Checking rule "+(i+1)+" of "+changed.size());
   long ruleId=((Number)changed.get(i).get("rule_id")).longValue();
   try{results.add(candidates.checkCurrent(ruleId));}catch(RuntimeException e){results.add(Map.of("rule_id",ruleId,"name",String.valueOf(changed.get(i).get("name")),"status","UNAVAILABLE"));}
  }
  var statuses=results.stream().map(r->String.valueOf(r.get("status"))).toList();
  String overall=statuses.contains("FAILED_EXPECTATION")?"FAILED":statuses.stream().anyMatch(s->s.equals("INCOMPLETE")||s.equals("UNAVAILABLE"))?"INCOMPLETE"
   :statuses.stream().allMatch("NO_FIXTURES"::equals)?"NO_TESTS":"PASSED";
  setCheck(updateId,overall,RuleDefinitionHistory.encode(results));
 }
 void setCheck(String updateId,String status,String json){
  records.update("UPDATE UpstreamUpdateEntity u SET u.checkStatus=?1,u.checkJson=?2 WHERE u.updateId=?3",status,json,updateId);
 }
 /** Releases this update's held rules: from now on they block like any other rule in their ruleset. */
 @Transactional
 public void approve(String updateId,long version,String actor){
  if(updateId==null||!updateId.matches("[a-f0-9-]{36}"))throw new IllegalArgumentException("Invalid update");
  var update=records.find(UpstreamUpdateEntity.class,updateId);
  if(update==null)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Update not found");
  if(update.getApprovedAt()!=null||update.getVersion()!=version)throw new ResponseStatusException(HttpStatus.CONFLICT,"Update changed; reload");
  var ids=decode(update.getAddedJson()).stream().map(a->((Number)a.get("rule_id")).longValue()).toList();
  if(!ids.isEmpty())records.update("UPDATE RuleEntity r SET r.stewardship.upstreamHoldSince=NULL,r.persistenceVersion=r.persistenceVersion+1 WHERE r.id IN ?1",ids);
  if(records.update("UPDATE UpstreamUpdateEntity u SET u.approvedBy=?1,u.approvedAt=?2,u.version=u.version+1 WHERE u.updateId=?3 AND u.version=?4 AND u.approvedAt IS NULL",actor,System.currentTimeMillis(),updateId,version)!=1)
   throw new ResponseStatusException(HttpStatus.CONFLICT,"Update changed; reload");
  LOG.info("Upstream update {} for {} approved by {}; {} held rules released",updateId,update.getModule(),actor,ids.size());
  TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){@Override public void afterCommit(){rules.invalidateRuleCache();}});
 }
 @Transactional(readOnly=true)
 public List<Map<String,Object>> list(){
  return records.list(UpstreamUpdateEntity.class,"SELECT u FROM UpstreamUpdateEntity u ORDER BY u.createdAt DESC,u.updateId",0,LISTED).stream().map(u->{
   Map<String,Object> v=new LinkedHashMap<>();
   v.put("id",u.getUpdateId());v.put("module",u.getModule());v.put("created_at",u.getCreatedAt());v.put("version",u.getVersion());
   v.put("added",decode(u.getAddedJson()));v.put("changed",decode(u.getChangedJson()));v.put("removed",decodeNames(u.getRemovedJson()));
   v.put("held",u.getHeldCount());v.put("check_status",u.getCheckStatus());v.put("check",u.getCheckJson()==null?List.of():decode(u.getCheckJson()));
   v.put("approved_by",u.getApprovedBy());v.put("approved_at",u.getApprovedAt());return v;}).toList();
 }
 private static List<Map<String,Object>> decode(String json){
  try{return RuleDefinitionHistory.JSON.readValue(json,new TypeReference<List<Map<String,Object>>>(){});}catch(Exception e){LOG.warn("Unreadable upstream update record");return List.of();}
 }
 private static List<String> decodeNames(String json){
  try{return RuleDefinitionHistory.JSON.readValue(json,new TypeReference<List<String>>(){});}catch(Exception e){LOG.warn("Unreadable upstream update record");return List.of();}
 }
}
