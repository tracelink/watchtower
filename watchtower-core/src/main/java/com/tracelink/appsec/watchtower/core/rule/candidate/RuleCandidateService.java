package com.tracelink.appsec.watchtower.core.rule.candidate;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.*;

import org.springframework.beans.factory.annotation.Value;
import com.tracelink.appsec.watchtower.core.persistence.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.watchtower.core.assistant.AssistantText;
import com.tracelink.appsec.watchtower.core.rule.*;

/** Human actions are separate from model suggestions and every enforcement write is revision-bound. */
@Service
public class RuleCandidateService {
 public record Draft(long ruleId,String baseRevision,JsonNode changes,String rationale,String reviewId) { }
 public record Fixture(long ruleId,String reference,String sha256,String expected,String cohort,String evidenceReference) { }
 public record CaseFixture(long ruleId,String baseRevision,String caseId,String expected,String cohort,boolean confirmed) { }
 public record Preparation(boolean assetsConfigured,boolean suiteUsable,List<String> reasons) { }
 public record Action(long version,String revision,String runId,String evidenceHash,String rationale) { }
 private final LedgerRepository records;private final RuleRepository rules;private final RuleService cache;
 private final RuleDefinitionHistory history;private final RuleCandidateTester tester;private final Path fixtureDirectory;
 public RuleCandidateService(LedgerRepository records,RuleRepository rules,RuleService cache,RuleDefinitionHistory history,
   RuleCandidateTester tester,@Value("${watchtower.rule-testing.fixture-directory:}") String fixtureDirectory) {
  this.records=records;this.rules=rules;this.cache=cache;this.history=history;this.tester=tester;
  try {this.fixtureDirectory=fixtureDirectory.isBlank()?null:Path.of(fixtureDirectory).toFile().getCanonicalFile().toPath();}
  catch(java.io.IOException e){throw new IllegalArgumentException("Fixture repository path unavailable");}
 }
 public RuleEntity current(long id) { return rules.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Rule unavailable")); }
 private RuleEntity locked(long id) {
  var entity=records.lock(RuleEntity.class,id);
  if(entity==null)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Rule unavailable");
  return current(id);
 }
 public RuleCandidateWorkspace workspace(long id) {
  var r=current(id).toDto();
  Map<String,Object> definition=RuleDefinitionHistory.JSON.convertValue(r,
    new com.fasterxml.jackson.core.type.TypeReference<LinkedHashMap<String,Object>>() {});
  var editable=fields(r);var metadata=new LinkedHashMap<String,RuleCandidateWorkspace.Field>();
  var reasons=new ArrayList<String>();
  if(!r.isCustom())reasons.add("Provided rules are maintained upstream. Use the module designer to author a supported custom rule.");
  else if(editable.isEmpty())reasons.add("This module has no candidate authoring adapter.");
  if(r.isRetired())reasons.add("This rule is retired.");
  if(tester.moduleUnavailable(r.getModule()))reasons.add("The module is disabled or its runtime is unavailable.");
  var bean=org.springframework.beans.BeanUtils.getPropertyDescriptors(r.getClass());
  for(String field:editable) {
   var property=Arrays.stream(bean).filter(p->p.getName().equals(field)).findFirst();
   if(!definition.containsKey(field)||property.isEmpty()) { reasons.add("The definition could not load field "+field+". Reload before authoring.");continue; }
   Class<?> type=property.get().getPropertyType();
   String kind=type==String.class?"string":type==boolean.class||type==Boolean.class?"boolean":
     type.isArray()||Collection.class.isAssignableFrom(type)?"array":
     Number.class.isAssignableFrom(type)||type.isPrimitive()?"number":"object";
   metadata.put(field,new RuleCandidateWorkspace.Field(kind,!type.isPrimitive()));
  }
  try(var factory=jakarta.validation.Validation.buildDefaultValidatorFactory()) {
   if(!factory.getValidator().validate(r).isEmpty())reasons.add("The current definition is invalid. Correct it in the rule editor first.");
  }
  return new RuleCandidateWorkspace(id,r.getRevision(),definition,editable,metadata,reasons.isEmpty(),List.copyOf(reasons),
    tester.available()&&!tester.moduleUnavailable(r.getModule()),list(id,0),fixtures(id),history.list(id,0));
 }
 /** Convert only at the service boundary; never change the canonical hash mapper. */
 @Transactional
 public String create(RuleCandidateWorkspace.DraftRequest request,String actor) {
  if(request.changes()==null||request.changes().isEmpty())throw new IllegalArgumentException("Use a bounded definition patch");
  validateJson(request.changes(),0,new int[]{0});
  return create(new Draft(request.ruleId(),request.baseRevision(),RuleDefinitionHistory.JSON.valueToTree(request.changes()),request.rationale(),request.reviewId()),actor);
 }
 private static void validateJson(Object value,int depth,int[] count) {
  if(depth>20||++count[0]>4096)throw new IllegalArgumentException("Definition patch is too complex");
  if(value instanceof Map<?,?> map) {
   for(var entry:map.entrySet()) {
    if(!(entry.getKey() instanceof String key)||key.length()>256)throw new IllegalArgumentException("Invalid field name");
    validateJson(entry.getValue(),depth+1,count);
   }
  }else if(value instanceof Collection<?> list)for(Object item:list)validateJson(item,depth+1,count);
  else if(value instanceof String text) {if(text.length()>65536)throw new IllegalArgumentException("Definition patch is too large");}
  else if(value!=null&&!(value instanceof Boolean)&&!(value instanceof Number))throw new IllegalArgumentException("Unsupported field value");
 }
 private Set<String> fields(RuleDto r) {
  if(!r.isCustom())return Set.of();
  return switch(r.getModule().toLowerCase(Locale.ROOT)) {
   case "regex" -> Set.of("regexPattern","fileExtension","message");
   case "opengrep" -> Set.of("definition","message");
   case "json" -> Set.of("query","fileExtension","message");
   case "pmd" -> Set.of("properties","message");
   case "eslint" -> Set.of("createFunction","schema","messages");
   case "betterleaks" -> Set.of("regex","keywords","entropy","secretGroup","filter","message");
   default -> Set.of();
  };
 }
 static RuleDto decode(String body,RuleDto original) {
  try { return RuleDefinitionHistory.JSON.readValue(body,original.getClass()); }
  catch(Exception e) { throw new IllegalArgumentException("Invalid rule definition"); }
 }
 /** Non-persisting validation shared by proposals and human drafts. Never executes an engine. */
 public RuleDto validate(Draft draft) { return validate(draft,current(draft.ruleId()).toDto()); }
 private RuleDto validate(Draft draft,RuleDto active) {
  tester.requireEnabled(active.getModule());requireCurrent(active,draft.baseRevision());
  if(active.isRetired()||fields(active).isEmpty())throw new IllegalArgumentException("This rule has no enabled candidate authoring adapter");
  if(draft.changes()==null||!draft.changes().isObject()||draft.changes().isEmpty()
    ||RuleDefinitionHistory.encode(draft.changes()).length()>65536)throw new IllegalArgumentException("Use a bounded definition patch");
  ObjectNode definition=(ObjectNode)RuleDefinitionHistory.JSON.valueToTree(active);
  draft.changes().fields().forEachRemaining(e->{
   if(!fields(active).contains(e.getKey()))throw new IllegalArgumentException("Unsupported candidate field");
   if(!e.getValue().equals(com.tracelink.appsec.watchtower.core.assistant.AssistantToolRegistry.redact(e.getValue())))
    throw new IllegalArgumentException("Remove secrets from the authored definition");
   definition.set(e.getKey(),e.getValue());
  });
  var candidate=decode(RuleDefinitionHistory.encode(definition),active);
  var matching=(ObjectNode)RuleDefinitionHistory.JSON.valueToTree(candidate);
  // A message-only edit changes finding identity, but does not improve matching behavior.
  matching.set("message",RuleDefinitionHistory.JSON.valueToTree(active.getMessage()));
  if(Objects.equals(decode(RuleDefinitionHistory.encode(matching),active).getRevision(),active.getRevision()))throw new IllegalArgumentException("Candidate must change matching behavior, not only a finding message");
  String revision=candidate.getRevision();if(revision==null||revision.equals(active.getRevision()))throw new IllegalArgumentException("Candidate must change executable behavior");
  try(var factory=jakarta.validation.Validation.buildDefaultValidatorFactory()) {
   if(!factory.getValidator().validate(candidate).isEmpty())throw new IllegalArgumentException("Candidate definition is invalid");
  }
  return candidate;
 }
 @Transactional
 public String create(Draft draft,String actor) {
  var active=locked(draft.ruleId()).toDto();var candidate=validate(draft,active);String revision=candidate.getRevision();
  String reviewId=uuid(draft.reviewId());
  if(reviewId!=null&&records.maps("SELECT reviewId AS review_id FROM RuleReviewItemEntity WHERE reviewId=?1 AND ruleId=?2 AND revision=?3 AND status IN ('OPEN','IN_REVIEW')",0,2147483647 ,reviewId,draft.ruleId(),draft.baseRevision()).isEmpty())
   throw new IllegalArgumentException("Choose an open review for this exact revision");
  history.record(active);String id=UUID.randomUUID().toString();long now=System.currentTimeMillis();
  records.insert(new RuleCandidateEntity(id,draft.ruleId(),active.getRevision(),RuleDefinitionHistory.hash(RuleDefinitionHistory.definition(active)),revision,RuleDefinitionHistory.definition(candidate),"DRAFT",reason(draft.rationale()),actor,reviewId,now,now,1L));
  audit(id,"CREATE",revision,null,null,actor,draft.rationale());return id;
 }
 public List<Map<String,Object>> list(long id,int offset) {
  page(offset);return records.maps("SELECT candidateId AS candidate_id,ruleId AS rule_id,baseRevision AS base_revision,revision AS revision,status AS status,rationale AS rationale,reviewer AS reviewer,reviewId AS review_id,createdAt AS created_at,updatedAt AS updated_at,version AS version FROM RuleCandidateEntity WHERE ruleId=?1 ORDER BY createdAt DESC,candidateId",offset,20 ,id);
 }
 public com.tracelink.appsec.watchtower.core.mvc.PagedResult<Map<String,Object>> page(long id,int page,int size) {
  com.tracelink.appsec.watchtower.core.rule.workflow.RuleReviewWorkspace.bounds(page,size);current(id);
  long count=records.scalar(Long.class,"SELECT COUNT(c) FROM RuleCandidateEntity c WHERE c.ruleId=?1",id);
  var rows=records.maps("SELECT c.candidateId AS candidate_id,c.revision AS revision,c.status AS status,c.rationale AS rationale FROM RuleCandidateEntity c WHERE c.ruleId=?1 ORDER BY c.createdAt DESC,c.candidateId",page*size,size,id);
  return com.tracelink.appsec.watchtower.core.rule.workflow.RuleReviewWorkspace.page(rows,page,size,count);
 }
 public Preparation preparation(long id) {
  current(id);var reasons=new ArrayList<String>();var rows=fixtures(id);
  if(fixtureDirectory==null)reasons.add("A versioned fixture directory is not configured.");
  if(rows.isEmpty())reasons.add("No reviewed executable fixtures are registered. A saved example reference alone is not an executable fixture.");
  for(String cohort:List.of("REGRESSION","HOLDOUT"))for(String expected:List.of("MATCH","NO_MATCH"))
   if(rows.stream().noneMatch(f->cohort.equals(f.get("cohort"))&&expected.equals(f.get("expected_behavior"))))reasons.add("Add a reviewed "+expected+" example to "+cohort+".");
  if(fixtureDirectory!=null&&!rows.isEmpty())try{loadFixtures(id);}catch(IllegalArgumentException|IllegalStateException e){reasons.add(e.getMessage());}
  return new Preparation(fixtureDirectory!=null,reasons.isEmpty(),List.copyOf(reasons));
 }
 public RuleRegressionCaseEntity caseReference(long ruleId,String caseId) {
  if(caseId==null)throw new IllegalArgumentException("Select a saved example");
  var item=records.find(RuleRegressionCaseEntity.class,uuid(caseId));
  if(item==null||item.ruleId!=ruleId)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Example reference unavailable for this rule");
  return item;
 }
 @Transactional
 public String registerCase(CaseFixture request,String actor) {
  var active=locked(request.ruleId()).toDto();var saved=caseReference(request.ruleId(),request.caseId());
  if(!Objects.equals(active.getRevision(),request.baseRevision())||!Objects.equals(saved.revision,request.baseRevision()))throw conflict("Rule revision changed; review the example against the current revision");
  if(!request.confirmed()||!Objects.equals(saved.expectedBehavior,request.expected()))throw new IllegalArgumentException("Confirm the saved expectation and selected collection");
  var existing=records.list(RuleEvaluationFixtureEntity.class,"SELECT f FROM RuleEvaluationFixtureEntity f WHERE f.ruleId=?1 AND f.evidenceRef=?2 AND f.cohort=?3 AND f.expectedBehavior=?4 AND f.fixtureHash=?5",0,1,request.ruleId(),"case/"+saved.caseId,request.cohort(),request.expected(),saved.fixtureHash);
  if(!existing.isEmpty()){readFixture(existing.getFirst().fixtureId,saved.fixtureRef,saved.fixtureHash);return existing.getFirst().fixtureId;}
  return fixture(new Fixture(request.ruleId(),saved.fixtureRef,saved.fixtureHash,request.expected(),request.cohort(),"case/"+saved.caseId),actor);
 }
 public Map<String,Object> candidate(String id) {
  var rows=records.maps("SELECT row FROM RuleCandidateEntity row WHERE candidateId=?1",0,2147483647 ,uuid(id));
  if(rows.isEmpty())throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Candidate unavailable");return rows.getFirst();
 }
 public List<Map<String,Object>> fixtures(long ruleId) { return records.maps("SELECT row FROM RuleEvaluationFixtureEntity row WHERE ruleId=?1 ORDER BY createdAt,fixtureId",0,21 ,ruleId); }
 @Transactional
 public String fixture(Fixture f,String actor) {
  locked(f.ruleId());reference(f.reference());reference(f.evidenceReference());
  if(f.sha256()==null||!f.sha256().matches("[a-f0-9]{64}")||!Set.of("MATCH","NO_MATCH").contains(f.expected())
    ||!Set.of("REGRESSION","HOLDOUT").contains(f.cohort()))throw new IllegalArgumentException("Reviewed hash, expectation and cohort required");
  if(fixtures(f.ruleId()).size()>=20)throw new IllegalArgumentException("The reviewed suite is limited to 20 fixtures");
  readFixture("preview",f.reference(),f.sha256());
  String id=UUID.randomUUID().toString();
  records.insert(new RuleEvaluationFixtureEntity(id,f.ruleId(),f.reference(),f.sha256(),f.expected(),f.cohort(),actor,f.evidenceReference(),System.currentTimeMillis()));return id;
 }
 private List<RuleTestSuite.File> loadFixtures(long ruleId) {
  if(fixtureDirectory==null)throw new IllegalStateException("A reviewed fixture repository is not configured");
  var rows=fixtures(ruleId);if(rows.isEmpty()||rows.size()>20)throw new IllegalArgumentException("Use 1–20 reviewed fixtures");
  return rows.stream().map(row->readFixture((String)row.get("fixture_id"),(String)row.get("fixture_ref"),(String)row.get("fixture_hash"))).toList();
 }
 private RuleTestSuite.File readFixture(String id,String ref,String hash) {
  if(fixtureDirectory==null)throw new IllegalStateException("A reviewed fixture repository is not configured");
  try {
   if(!fixtureDirectory.toRealPath().equals(fixtureDirectory))throw new IllegalArgumentException("Fixture repository cannot use linked paths");
    reference(ref);Path file=fixtureDirectory.resolve(ref);
    if(!file.startsWith(fixtureDirectory)||!file.toRealPath().equals(file)||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)
      ||Files.size(file)>65536)throw new IllegalArgumentException("Unavailable or oversized reviewed fixture");
    byte[] bytes=Files.readAllBytes(file);
    var decoder=java.nio.charset.StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT);
    String content=decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString();
    if(!RuleDefinitionHistory.hash(content).equals(hash)||!AssistantText.redact(content).equals(content))
     throw new IllegalArgumentException("Fixture hash changed or fixture contains secrets");
    return new RuleTestSuite.File(id,file.getFileName().toString(),content);
  }catch(java.io.IOException e){throw new IllegalArgumentException("Reviewed fixture asset unavailable");}
 }
 @Transactional
 public String prepareRun(String candidateId,String actor) {
  if(!tester.available())throw new IllegalStateException("Rule testing is disabled or unavailable");
  var c=candidate(candidateId);var active=locked(((Number)c.get("rule_id")).longValue()).toDto();checkBase(active,c);tester.requireRuntime(active.getModule());
  if(!Set.of("DRAFT","SHADOW").contains(c.get("status")))throw conflict("Candidate is no longer testable");
  var preparation=preparation(active.getId());if(!preparation.suiteUsable())throw new IllegalArgumentException(String.join(" ",preparation.reasons()));
  if(records.scalar(Long.class,"SELECT COUNT(r) FROM RuleCandidateRunEntity r WHERE r.activeCandidate=?1",candidateId)>0)throw conflict("A test is already queued or running");
  String id=UUID.randomUUID().toString();records.insert(new RuleCandidateRunEntity(id,candidateId,(String)c.get("base_revision"),(String)c.get("revision"),"0".repeat(64),"{}","QUEUED",actor,System.currentTimeMillis(),candidateId,null,null));return id;
 }
 public List<Map<String,Object>> runs(String id) {candidate(id);return records.maps("SELECT runId AS run_id,evidenceHash AS evidence_hash,evidenceJson AS evidence_json,status AS status,actor AS actor,createdAt AS created_at FROM RuleCandidateRunEntity WHERE candidateId=?1 ORDER BY createdAt DESC,runId",0,20 ,uuid(id));}
 public void failRun(String id) {records.update("UPDATE RuleCandidateRunEntity SET status='FAILED',activeCandidate=NULL WHERE runId=?1 AND status='QUEUED'" ,uuid(id));}
 @org.springframework.scheduling.annotation.Scheduled(fixedDelayString="${watchtower.rule-testing.reconcile-delay-ms:60000}")
 public void reconcileRuns() {
  long now=System.currentTimeMillis();
  // A crash between reserving a run and creating its generic job must not pin its slot forever.
  String liveJob="NOT EXISTS (SELECT j.id FROM AsyncJobEntity j WHERE j.type=com.tracelink.appsec.watchtower.core.job.AsyncJobType.RULE_CANDIDATE_TEST AND j.payload=r.runId AND j.status IN (com.tracelink.appsec.watchtower.core.job.AsyncJobStatus.QUEUED,com.tracelink.appsec.watchtower.core.job.AsyncJobStatus.RUNNING))";
  var abandoned=records.maps("SELECT r.runId AS run_id FROM RuleCandidateRunEntity r WHERE r.activeCandidate IS NOT NULL AND r.createdAt<?1 AND (r.status='QUEUED' OR (r.status='RUNNING' AND r.leaseUntil<?2)) AND "+liveJob+" ORDER BY r.createdAt",0,100,now-900000,now);
  for(var row:abandoned)records.update("UPDATE RuleCandidateRunEntity r SET r.status='FAILED',r.activeCandidate=NULL,r.claimToken=NULL WHERE r.runId=?1 AND r.activeCandidate IS NOT NULL AND r.createdAt<?2 AND (r.status='QUEUED' OR (r.status='RUNNING' AND r.leaseUntil<?3)) AND "+liveJob,row.get("run_id"),now-900000,now);
 }
 public void run(String runId,Runnable reauthorize) {
  String token=UUID.randomUUID().toString();long now=System.currentTimeMillis();
  if(records.update("UPDATE RuleCandidateRunEntity SET status='RUNNING',claimToken=?1,leaseUntil=?2 WHERE runId=?3 AND (status='QUEUED' OR (status='RUNNING' AND leaseUntil<?4))" ,token,now+180000,uuid(runId),now)!=1)return;
  try {
   reauthorize.run();var run=records.maps("SELECT row FROM RuleCandidateRunEntity row WHERE runId=?1",0,2147483647 ,runId).getFirst();
   var c=candidate((String)run.get("candidate_id"));var active=current(((Number)c.get("rule_id")).longValue()).toDto();checkBase(active,c);
   if(!Set.of("DRAFT","SHADOW").contains(c.get("status")))throw conflict("Candidate changed");
   var rows=fixtures(active.getId());var files=loadFixtures(active.getId());
   var request=new RuleTestSuite.Request(active.getModule().toLowerCase(Locale.ROOT),active.getRuleDesignation().name(),RuleDefinitionHistory.definition(active),(String)c.get("definition_json"),files);
   String executionProfile=tester.identity();reauthorize.run();var result=tester.test(request);reauthorize.run();
   tester.requireEnabled(active.getModule());if(!executionProfile.equals(tester.identity()))throw conflict("Execution policy changed");
   // Labels are supplied by the human-reviewed records, never accepted from the engine.
   var comparisons=new ArrayList<Map<String,Object>>();boolean complete=true,passing=true;
   for(var pair:result.cases()) {
    var fixture=rows.stream().filter(f->f.get("fixture_id").equals(pair.fixtureId())).findFirst().orElseThrow();
    boolean expected="MATCH".equals(fixture.get("expected_behavior")),matched=!pair.candidate().matches().isEmpty();
    complete&=pair.base().complete()&&pair.candidate().complete();passing&=expected==matched&&pair.candidate().complete();
    var detail=new LinkedHashMap<String,Object>();detail.put("fixture",fixture);detail.put("base",pair.base());detail.put("candidate",pair.candidate());
    var old=new HashSet<>(pair.base().matches());var next=new HashSet<>(pair.candidate().matches());
    detail.put("newlyMatched",next.stream().filter(m->!old.contains(m)).toList());detail.put("newlyMissed",old.stream().filter(m->!next.contains(m)).toList());
    detail.put("expectationPassed",expected==matched&&pair.candidate().complete());comparisons.add(detail);
   }
   checkBase(current(active.getId()).toDto(),c);
   String evidence=RuleDefinitionHistory.encode(Map.of("baseRevision",c.get("base_revision"),"candidateRevision",c.get("revision"),"executionIdentity",executionProfile,"fixtures",comparisons,
     "limits",Map.of("inputMiB",2,"fixtureCount",20,"wallSeconds",110,"javaHeapMiB",512,"outputMiB",1,"mode","direct","isolation","deferred by user"),"complete",complete,"passing",passing));
   records.update("UPDATE RuleCandidateRunEntity SET evidenceJson=?1,evidenceHash=?2,status=?3,activeCandidate=NULL WHERE runId=?4 AND status='RUNNING' AND claimToken=?5" ,evidence,RuleDefinitionHistory.hash(evidence),complete?(passing?"PASSED":"FAILED_EXPECTATION"):"INCOMPLETE",runId,token);
  } catch(RuntimeException e) {
   records.update("UPDATE RuleCandidateRunEntity SET status='FAILED',activeCandidate=NULL WHERE runId=?1 AND status='RUNNING' AND claimToken=?2" ,runId,token);
   throw new IllegalStateException("Rule test did not complete; check grants, exact revisions, reviewed fixtures and engine runtime");
  }
 }
 /**
  * R5.4: runs a rule's current definition against its reviewed fixtures (no candidate involved).
  * Human labels decide pass/fail; a missing runtime or fixture file is UNAVAILABLE, never a pass.
  */
 public Map<String,Object> checkCurrent(long ruleId) {
  var active=current(ruleId).toDto();var rows=fixtures(ruleId);
  if(rows.isEmpty())return Map.of("rule_id",ruleId,"name",active.getName(),"status","NO_FIXTURES","fixtures",0);
  try {
   tester.requireRuntime(active.getModule());String definition=RuleDefinitionHistory.definition(active);
   var result=tester.test(new RuleTestSuite.Request(active.getModule().toLowerCase(Locale.ROOT),active.getRuleDesignation().name(),definition,definition,loadFixtures(ruleId)));
   boolean complete=true,passing=true;
   for(var pair:result.cases()) {
    var fixture=rows.stream().filter(f->f.get("fixture_id").equals(pair.fixtureId())).findFirst().orElseThrow();
    boolean expected="MATCH".equals(fixture.get("expected_behavior")),matched=!pair.candidate().matches().isEmpty();
    complete&=pair.candidate().complete();passing&=expected==matched&&pair.candidate().complete();
   }
   return Map.of("rule_id",ruleId,"name",active.getName(),"status",complete?(passing?"PASSED":"FAILED_EXPECTATION"):"INCOMPLETE","fixtures",rows.size());
  } catch(RuntimeException e) {return Map.of("rule_id",ruleId,"name",active.getName(),"status","UNAVAILABLE","fixtures",rows.size());}
 }
 @Transactional
 public void transition(String id,String action,Action approval,String actor) {
  var c=candidate(id);long ruleId=((Number)c.get("rule_id")).longValue();var entity=locked(ruleId);var active=entity.toDto();
  // Reload the candidate after obtaining the shared lock so simultaneous actions cannot race.
  c=candidate(id);if(((Number)c.get("version")).longValue()!=approval.version()||!Objects.equals(c.get("revision"),approval.revision()))throw conflict("Candidate changed; reload");
  String status=(String)c.get("status"),next;
  switch(action) {
   case "SHADOW" -> {
    tester.requireRuntime(active.getModule());
    checkBase(active,c);if(!status.equals("DRAFT"))throw conflict("Only a draft can enter shadow");requireEvidence(c,approval);
    if(!records.maps("SELECT candidateId AS candidate_id FROM RuleCandidateEntity WHERE ruleId=?1 AND status='SHADOW'",0,2147483647 ,ruleId).isEmpty())throw conflict("Only one shadow candidate per logical rule is allowed");
    next="SHADOW";
   }
   case "REJECT" -> {if(!Set.of("DRAFT","SHADOW").contains(status))throw conflict("Candidate is closed");next="REJECTED";}
   case "PROMOTE" -> {tester.requireRuntime(active.getModule());checkBase(active,c);if(!status.equals("SHADOW"))throw conflict("Review shadow evidence before promotion");requireEvidence(c,approval);replace(entity,decode((String)c.get("definition_json"),active));next="PROMOTED";}
   case "ROLLBACK" -> {
    if(!status.equals("PROMOTED")||!active.getRevision().equals(c.get("revision")))throw conflict("Active rule no longer matches this promotion");
    var versions=records.maps("SELECT definitionJson AS definition_json FROM RuleDefinitionVersionEntity WHERE ruleId=?1 AND definitionHash=?2",0,2147483647 ,ruleId,c.get("base_definition_hash"));
    if(versions.size()!=1)throw conflict("Previous definition unavailable");
    replace(entity,decode((String)versions.getFirst().get("definition_json"),active));next="ROLLED_BACK";
   }
   default -> throw new IllegalArgumentException("Unknown candidate action");
  }
  records.update("UPDATE RuleCandidateEntity SET status=?1,updatedAt=?2,version=version+1 WHERE candidateId=?3 AND version=?4" ,next,System.currentTimeMillis(),id,approval.version());
  audit(id,action,approval.revision(),approval.runId(),approval.evidenceHash(),actor,approval.rationale());
  if(c.get("review_id")!=null&&Set.of("PROMOTE","REJECT").contains(action)) {
   String reviewStatus=action.equals("PROMOTE")?"ACCEPTED":"REJECTED";String rationale=reason(approval.rationale());
   records.update("UPDATE RuleReviewItemEntity SET status=?1,outcome=?2,updatedAt=?3,version=version+1 WHERE reviewId=?4 AND ruleId=?5" ,reviewStatus,rationale,System.currentTimeMillis(),c.get("review_id"),ruleId);
   records.insert(new RuleReviewAuditEntity(null,(String)c.get("review_id"),reviewStatus,actor,rationale,System.currentTimeMillis()));
  }
 }
 private void replace(RuleEntity existing,RuleDto definition) {
  // Preserve current name, owner, priority, rulesets and lifecycle; these are independent policies.
  var now=existing.toDto();definition.setName(now.getName());definition.setPriority(now.getPriority());definition.setRulesets(now.getRulesets());
  var replacement=definition.toEntity();replacement.setId(existing.getId());replacement.setAuthor(existing.getAuthor());
  replacement.preserveStewardshipFrom(existing);replacement.getRulesets().addAll(existing.getRulesets());replacement.refreshRevision();
  history.record(now);var saved=rules.saveAndFlush(replacement);history.record(saved.toDto());cache.invalidateRuleCache();
 }
 private void requireEvidence(Map<String,Object> c,Action approval) {
  var rows=records.maps("SELECT row FROM RuleCandidateRunEntity row WHERE runId=?1 AND candidateId=?2 AND status='PASSED' AND evidenceHash=?3",0,2147483647 ,uuid(approval.runId()),c.get("candidate_id"),approval.evidenceHash());
  if(rows.size()!=1)throw conflict("Exact passing test evidence required");
  var row=rows.getFirst();if(!row.get("candidate_revision").equals(c.get("revision"))||!row.get("base_revision").equals(c.get("base_revision")))throw conflict("Test revisions changed");
  try {
   var evidence=RuleDefinitionHistory.JSON.readTree((String)row.get("evidence_json"));
   if(!tester.available()||!tester.identity().equals(evidence.path("executionIdentity").asText()))throw conflict("Rule test execution profile changed; retest");
   var evaluated=new ArrayList<JsonNode>();evidence.path("fixtures").forEach(f->evaluated.add(f.path("fixture")));
   var actual=fixtures(((Number)c.get("rule_id")).longValue());
   if(!new HashSet<>(evaluated.stream().map(RuleDefinitionHistory::encode).toList()).equals(new HashSet<>(actual.stream().map(RuleDefinitionHistory::encode).toList())))throw conflict("Reviewed fixture collection changed; retest");
   // Recheck on-disk hashes even when metadata has not changed.
   loadFixtures(((Number)c.get("rule_id")).longValue());
   for(String cohort:List.of("REGRESSION","HOLDOUT"))for(String expected:List.of("MATCH","NO_MATCH"))
    if(actual.stream().noneMatch(f->cohort.equals(f.get("cohort"))&&expected.equals(f.get("expected_behavior"))))
     throw conflict("Positive and clean reviewed fixtures are required in both regression and held-out sets");
  }catch(java.io.IOException e){throw conflict("Test evidence unavailable");}
 }
 private static void checkBase(RuleDto active,Map<String,Object> c) {
  requireCurrent(active,(String)c.get("base_revision"));
  if(active.isRetired()||!RuleDefinitionHistory.hash(RuleDefinitionHistory.definition(active)).equals(c.get("base_definition_hash")))throw conflict("Active definition or policy changed; create a new candidate");
 }
 private static void requireCurrent(RuleDto active,String revision) {if(revision==null||!revision.equals(active.getRevision()))throw conflict("Active revision changed; reload");}
 private void audit(String id,String action,String revision,String run,String hash,String actor,String rationale) {
  records.insert(new RuleCandidateActionEntity(UUID.randomUUID().toString(),id,action,revision,uuid(run),hash,actor,reason(rationale),System.currentTimeMillis()));
 }
 public List<Map<String,Object>> audit(String id){candidate(id);return records.maps("SELECT row FROM RuleCandidateActionEntity row WHERE candidateId=?1 ORDER BY createdAt DESC,actionId",0,50 ,uuid(id));}
 static String uuid(String value){return value==null?null:UUID.fromString(value).toString();}
 static String reason(String text){String result=AssistantText.bounded(text,300);if(result.isBlank())throw new IllegalArgumentException("Human rationale required");return result;}
 static void reference(String value){if(value==null||!value.matches("[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")||value.contains("..")||value.contains("//"))throw new IllegalArgumentException("Use a versioned reviewed reference");}
 static void page(int offset){if(offset<0||offset>10000)throw new IllegalArgumentException("Invalid page");}
 static ResponseStatusException conflict(String message){return new ResponseStatusException(HttpStatus.CONFLICT,message);}
}
