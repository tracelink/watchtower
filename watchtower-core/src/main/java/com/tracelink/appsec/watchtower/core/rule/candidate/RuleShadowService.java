package com.tracelink.appsec.watchtower.core.rule.candidate;

import java.nio.file.*;
import java.util.*;
import com.tracelink.appsec.watchtower.core.persistence.*;
import org.springframework.stereotype.Service;
import com.tracelink.appsec.watchtower.core.assistant.AssistantAccess;
import com.tracelink.appsec.watchtower.core.assistant.AssistantText;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;

/** Separately sampled shadow evidence never enters normal findings, comments or health counts. */
@Service
public class RuleShadowService {
 private final org.springframework.transaction.support.TransactionTemplate transaction;private final LedgerRepository records;private final RuleCandidateTester tester;private final AssistantAccess access;
 public RuleShadowService(LedgerRepository records,RuleCandidateTester tester,AssistantAccess access,org.springframework.transaction.PlatformTransactionManager tm){this.transaction=new org.springframework.transaction.support.TransactionTemplate(tm);this.records=records;this.tester=tester;this.access=access;}
 public boolean enabled(){return tester.available();}
 public List<Map<String,Object>> observations(String id,int days){
  if(days<1||days>90)throw new IllegalArgumentException("Invalid comparison window");
  return records.maps("SELECT row FROM RuleShadowObservationEntity row WHERE candidateId=?1 AND createdAt>=?2 ORDER BY createdAt DESC,observationId",0,50 ,RuleCandidateService.uuid(id),System.currentTimeMillis()-days*86400000L);
 }
 public void compare(String type,long scanId,CodeScanConfig config) {
  if(!enabled()||scanId<=0||config.getRuleset()==null)return;
  var selected=new HashMap<Long,com.tracelink.appsec.watchtower.core.rule.RuleDto>();
  config.getRuleset().getAllRules().forEach(rule->{if(rule.getId()!=null&&rule.getRevision()!=null)selected.put(rule.getId(),rule);});
  // One bounded query per scan, rather than one query for every active engine rule.
  var candidates=records.maps("SELECT row FROM RuleCandidateEntity row WHERE status='SHADOW' ORDER BY createdAt,candidateId",0,1000);
  int executions=0;
  for(var c:candidates) {
   if(executions>=3)break;
   var rule=selected.get(((Number)c.get("rule_id")).longValue());
   if(rule==null||!rule.getRevision().equals(c.get("base_revision"))||tester.moduleUnavailable(rule.getModule()))continue;
   String candidateId=(String)c.get("candidate_id");
   String key=RuleDefinitionHistory.hash(type+":"+scanId+":"+candidateId);
   if(!RuleDefinitionHistory.hash(RuleDefinitionHistory.definition(rule)).equals(c.get("base_definition_hash"))
     ||!records.maps("SELECT observationId AS observation_id FROM RuleShadowObservationEntity WHERE observationId=?1",0,2147483647 ,key).isEmpty())continue;
   var approved=records.maps("SELECT actor AS actor FROM RuleCandidateActionEntity WHERE candidateId=?1 AND action='SHADOW' ORDER BY createdAt DESC",0,1 ,candidateId);
   if(approved.isEmpty())continue;String actor=(String)approved.getFirst().get("actor");
   long started=System.nanoTime();String status="FAILED";Map<String,Object> evidence=new LinkedHashMap<>();
   evidence.put("scope","Sample of at most 20 text files, 64 KiB each; absent matches do not prove repository coverage");
   evidence.put("normalEnforcementChanged",false);evidence.put("maxExtraServiceRequestsPerScan",3);
   try {
    authorize(actor);Path root=config.getWorkingDirectory().toRealPath();var files=new ArrayList<RuleTestSuite.File>();
    var references=new ArrayList<Map<String,Object>>();int omitted=0,visited=0;
    try(var paths=Files.walk(root)) {
     var iterator=paths.iterator();
     while(iterator.hasNext()&&visited++<10000&&files.size()<20) {
      Path path=iterator.next();if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))continue;
      String relative=root.relativize(path).toString().replace('\\','/');
      if(!path.toRealPath().equals(path)||Files.size(path)>65536||relative.matches("(?i).*(^|/)(\\.git|node_modules|\\.env[^/]*|credentials|[^/]*\\.(pem|key))(/|$).*")
        ||!path.getFileName().toString().matches("[A-Za-z0-9][A-Za-z0-9._-]{0,99}")){omitted++;continue;}
      String content;
      try{content=Files.readString(path);}catch(java.io.IOException e){omitted++;continue;}
      if(!AssistantText.redact(content).equals(content)){omitted++;continue;}
      String id=UUID.nameUUIDFromBytes(relative.getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
      files.add(new RuleTestSuite.File(id,path.getFileName().toString(),content));
      references.add(Map.of("id",id,"path",AssistantText.redact(relative),"sha256",RuleDefinitionHistory.hash(content)));
     }
    }
    evidence.put("files",references);evidence.put("omitted",omitted);evidence.put("visited",visited);
    if(files.isEmpty()){status="NO_SAMPLE";}else {
     executions++;authorize(actor);
     var request=new RuleTestSuite.Request(rule.getModule().toLowerCase(Locale.ROOT),rule.getRuleDesignation().name(),RuleDefinitionHistory.definition(rule),(String)c.get("definition_json"),files);
     var results=tester.test(request);authorize(actor);
     evidence.put("comparisons",results);status=results.cases().stream().allMatch(p->p.base().complete()&&p.candidate().complete())?"COMPLETE":"INCOMPLETE";
    }
   }catch(Exception e){evidence.put("limitation","Sample unavailable, access revoked or direct engine evaluation failed");}
   storeObservation(new RuleShadowObservationEntity(key,candidateId,type,scanId,(String)c.get("base_revision"),(String)c.get("revision"),tester.identity(),status,RuleDefinitionHistory.encode(evidence),(System.nanoTime()-started)/1000000,System.currentTimeMillis()));
  }
 }
 private void storeObservation(RuleShadowObservationEntity observation) {
  transaction.executeWithoutResult(s->{
   // All observations for a candidate share its row lock; duplicate scan deliveries become no-ops.
   records.lock(RuleCandidateEntity.class,observation.candidateId);
   if(records.find(RuleShadowObservationEntity.class,observation.observationId)==null)records.insert(observation);
  });
 }
 private void authorize(String actor){for(String grant:List.of("Rule Modify","Assistant Source Read","Scan Results View"))access.require(actor,grant);}
}
