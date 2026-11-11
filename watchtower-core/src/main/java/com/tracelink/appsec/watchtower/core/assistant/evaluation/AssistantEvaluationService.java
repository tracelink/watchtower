package com.tracelink.appsec.watchtower.core.assistant.evaluation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.persistence.AssistantTurnEntity;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory;

/**
 * Plan step 13 activation gate. Sends a fixed, versioned question set through the real chat pipeline
 * (same tools, grants, budgets and audit) as the admin who starts the run, one turn at a time. Each
 * answer is checked deterministically (tools used, rule references, decline wording, forbidden
 * claims); engineers then score every answer. Only checks, scores and turn references are stored —
 * the answers themselves stay in the normal expiring transcripts.
 */
@Service
public class AssistantEvaluationService {
 /** Pause between polls; replaced in tests so a fake worker can complete turns deterministically. */
 @FunctionalInterface public interface Sleeper { void sleep(long millis) throws InterruptedException; }
 private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(AssistantEvaluationService.class);
 static final String CASES="/assistant/evaluation/cases-v1.json",LOCK="assistant-evaluation";
 static final int MAX_CASES=20,MAX_NOTE=300;
 static final long POLL_MILLIS=2000,BUSY_RETRY_MILLIS=5000,SUBMIT_PATIENCE_MILLIS=10*60*1000L,STALE_RUN_MILLIS=2*60*60*1000L;
 /** The assistant has only read tools; anything else in the evidence would be a change. */
 private static final java.util.regex.Pattern READ_TOOL=java.util.regex.Pattern.compile("(get|list|search|read)_[a-z_]+");
 private static final String BUDGET_STOP="SHARED_BUDGET";
 private static final Set<String> TERMINAL_TURN=Set.of("COMPLETED","FAILED","CANCELED"),FINAL_RESULT=Set.of("COMPLETED","FAILED");
 private final LedgerRepository records;private final AssistantPersistence db;private final AssistantSettingsService settings;private final AssistantAccess access;
 private final RuleService rules;private final ModuleControlService controls;private final ObjectProvider<AsyncJobService> jobs;
 private final TransactionTemplate separate;private final Sleeper sleeper;
 @Autowired
 public AssistantEvaluationService(LedgerRepository records,AssistantPersistence db,AssistantSettingsService settings,AssistantAccess access,RuleService rules,
   ModuleControlService controls,ObjectProvider<AsyncJobService> jobs,PlatformTransactionManager transactions){
  this(records,db,settings,access,rules,controls,jobs,transactions,Thread::sleep);
 }
 public AssistantEvaluationService(LedgerRepository records,AssistantPersistence db,AssistantSettingsService settings,AssistantAccess access,RuleService rules,
   ModuleControlService controls,ObjectProvider<AsyncJobService> jobs,PlatformTransactionManager transactions,Sleeper sleeper){
  this.records=records;this.db=db;this.settings=settings;this.access=access;this.rules=rules;this.controls=controls;this.jobs=jobs;this.sleeper=sleeper;
  separate=new TransactionTemplate(transactions);separate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
 }
 private void requireRunner(String actor){access.require(actor,"Assistant Admin");access.require(actor,"Assistant Use");}

 @Transactional
 public String start(String model,String effort,String actor){
  requireRunner(actor);
  var readiness=settings.readiness();if(!readiness.ready())throw new ResponseStatusException(HttpStatus.CONFLICT,readiness.message()+" Grant Assistant Use only to evaluators before turning chat on.");
  var config=settings.get().settings();String chosenModel=model==null||model.isBlank()?config.defaultModel():model,chosenEffort=effort==null?config.defaultEffort():effort;
  config.model(chosenModel,chosenEffort);
  JsonNode catalog=catalog();var questions=expand(catalog);
  if(questions.isEmpty())throw new ResponseStatusException(HttpStatus.CONFLICT,"No active rules in enabled modules to ask about");
  records.lockScope(LOCK);long now=System.currentTimeMillis();
  // A run whose job died long ago no longer blocks a new one.
  records.update("UPDATE AssistantEvaluationRunEntity r SET r.status='FAILED',r.finishedAt=?1 WHERE r.status IN ('QUEUED','RUNNING') AND r.updatedAt<?2",now,now-STALE_RUN_MILLIS);
  if(records.scalar(Long.class,"SELECT COUNT(r) FROM AssistantEvaluationRunEntity r WHERE r.status IN ('QUEUED','RUNNING')")>0)
   throw new ResponseStatusException(HttpStatus.CONFLICT,"An evaluation is already running");
  String runId=UUID.randomUUID().toString();
  records.insert(new AssistantEvaluationRunEntity(runId,catalog.path("version").asText(),actor,chosenModel,chosenEffort,questions.size(),now));
  for(int i=0;i<questions.size();i++){
   var q=questions.get(i);
   records.insert(new AssistantEvaluationResultEntity(UUID.randomUUID().toString(),runId,i,q.path("case_id").asText(),q.path("category").asText(),RuleDefinitionHistory.hash(q.path("prompt").asText()),RuleDefinitionHistory.encode(q)));
  }
  TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){@Override public void afterCommit(){
   try{separate.executeWithoutResult(tx->{if(jobs.getObject().enqueue(AsyncJobType.ASSISTANT_EVALUATION,runId,"assistant-evaluation:"+runId,actor).isEmpty())finishRun(runId,"FAILED");});}
   catch(RuntimeException e){LOG.warn("Evaluation run {} could not be queued",runId,e);finishRun(runId,"FAILED");}
  }});
  return runId;
 }
 static JsonNode catalog(){
  try(var in=AssistantEvaluationService.class.getResourceAsStream(CASES)){return AssistantState.mapper().readTree(in);}
  catch(IOException|RuntimeException e){throw new IllegalStateException("Evaluation question set unavailable",e);}
 }
 /** Fills placeholders from this installation's active rules in enabled modules (lowest id first). */
 List<ObjectNode> expand(JsonNode catalog){
  var active=rules.getRules().stream().filter(r->r.getId()!=null&&!r.isRetired()&&(controls==null||controls.enabled(r.getModule())))
   .sorted(Comparator.comparing((RuleDto r)->r.getModule()).thenComparing(RuleDto::getId)).toList();
  if(active.isEmpty())return List.of();
  Map<String,RuleDto> firstByModule=new TreeMap<>();active.forEach(r->firstByModule.putIfAbsent(r.getModule(),r));
  // Prefer a rule whose module has a second rule, so the comparison question can always be asked.
  RuleDto primary=active.stream().filter(r->active.stream().anyMatch(o->o.getModule().equals(r.getModule())&&!o.getId().equals(r.getId()))).findFirst().orElse(active.getFirst());var second=active.stream().filter(r->r.getModule().equals(primary.getModule())&&!r.getId().equals(primary.getId())).findFirst();
  List<ObjectNode> questions=new ArrayList<>();
  for(var spec:catalog.path("cases")){
   if(spec.path("per_module").asBoolean()){for(var rule:firstByModule.values())questions.add(question(catalog,spec,spec.path("id").asText()+":"+rule.getModule(),rule,null));}
   else if(spec.path("needs_second_rule").asBoolean()){if(second.isPresent())questions.add(question(catalog,spec,spec.path("id").asText(),primary,second.get()));}
   else questions.add(question(catalog,spec,spec.path("id").asText(),primary,null));
  }
  return questions.size()>MAX_CASES?questions.subList(0,MAX_CASES):questions;
 }
 private static ObjectNode question(JsonNode catalog,JsonNode spec,String caseId,RuleDto rule,RuleDto other){
  Map<String,String> values=new HashMap<>();
  values.put("{rule_id}",String.valueOf(rule.getId()));values.put("{rule_name}",Objects.toString(rule.getName(),""));values.put("{module}",rule.getModule());
  String revision=rule.getRevision();values.put("{revision_prefix}",revision==null?String.valueOf(rule.getId()):revision.substring(0,Math.min(12,revision.length())));
  if(other!=null)values.put("{rule_id_2}",String.valueOf(other.getId()));
  var q=AssistantState.mapper().createObjectNode();
  q.put("case_id",caseId);q.put("category",spec.path("category").asText());q.put("rule_id",rule.getId());q.put("prompt",fill(spec.path("prompt").asText(),values));
  for(String field:List.of("require_tools","require_any_text","require_all_text","forbid_text")){
   var source=spec.path(field);if(source.isTextual())source=catalog.path(source.asText());
   ArrayNode list=q.putArray(field);source.forEach(v->list.add(fill(v.asText(),values)));
  }
  var forbid=(ArrayNode)q.get("forbid_text");if(spec.has("forbid"))catalog.path(spec.path("forbid").asText()).forEach(v->forbid.add(v.asText()));
  return q;
 }
 private static String fill(String text,Map<String,String> values){for(var e:values.entrySet())text=text.replace(e.getKey(),e.getValue());return text;}

 /** Job body: one question at a time (each user has one active turn). Re-runnable after a crash. */
 public void run(String runId,Consumer<String> progress){
  var run=records.find(AssistantEvaluationRunEntity.class,runId);
  if(run==null||!Set.of("QUEUED","RUNNING").contains(run.getStatus()))return;
  touch(runId,"RUNNING");
  var results=records.list(AssistantEvaluationResultEntity.class,"SELECT r FROM AssistantEvaluationResultEntity r WHERE r.runId=?1 ORDER BY r.position",0,MAX_CASES,runId);
  for(int i=0;i<results.size();i++){
   var result=results.get(i);if(FINAL_RESULT.contains(result.getStatus()))continue;
   // Another start may have marked this run stale; stop writing instead of racing the new run.
   var latest=records.find(AssistantEvaluationRunEntity.class,runId);if(latest==null||!"RUNNING".equals(latest.getStatus()))return;
   String note="Question "+(i+1)+" of "+results.size();progress.accept(note);
   try{requireRunner(run.getRequestedBy());}catch(AccessDeniedException e){failRemaining(runId,"ACCESS_REVOKED");finishRun(runId,"FAILED");return;}
   if(!settings.available()){failRemaining(runId,"CHAT_DISABLED");finishRun(runId,"FAILED");return;}
   try{ask(run,result,()->{progress.accept(note);touch(runId,"RUNNING");});}
   catch(InterruptedException e){Thread.currentThread().interrupt();return;}
   catch(org.springframework.dao.DataAccessException e){throw new com.tracelink.appsec.watchtower.core.job.RetryLaterException("Database unavailable during evaluation",60);}
   catch(RuntimeException|IOException e){LOG.warn("Evaluation question {} could not complete",result.getCaseId());fail(result.getResultId(),"EVALUATION_ERROR");}
   // The shared daily budget will refuse every later question too: stop instead of reporting Completed.
   // A query, not find(): the bulk update above does not refresh an entity already loaded.
   var codes=records.list(String.class,"SELECT r.errorCode FROM AssistantEvaluationResultEntity r WHERE r.resultId=?1",0,1,result.getResultId());
   if(!codes.isEmpty()&&BUDGET_STOP.equals(codes.getFirst())){failRemaining(runId,BUDGET_STOP);finishRun(runId,"STOPPED");return;}
  }
  finishRun(runId,"DONE");
 }
 private void ask(AssistantEvaluationRunEntity run,AssistantEvaluationResultEntity result,Runnable heartbeat)throws IOException,InterruptedException{
  JsonNode spec=AssistantState.mapper().readTree(result.getSpecJson());String turnId=result.getTurnId();
  if(turnId==null){
   // Deterministic idempotency key: a resumed job finds the same turn instead of asking twice.
   String key=UUID.nameUUIDFromBytes(("assistant-evaluation:"+result.getResultId()).getBytes(StandardCharsets.UTF_8)).toString();
   long giveUp=System.currentTimeMillis()+SUBMIT_PATIENCE_MILLIS;AssistantPersistence.Turn turn=null;
   while(turn==null){
    try{turn=db.submit(new AssistantPersistence.Submit(null,key,spec.path("prompt").asText(),run.getModel(),run.getEffort()),run.getRequestedBy());}
    catch(ResponseStatusException e){
     // The evaluator's own chat turn or a full queue: wait, then retry with the same key.
     // An idempotency conflict is permanent; only a busy user or a full queue is worth waiting for.
     boolean busy=(e.getStatusCode().value()==409||e.getStatusCode().value()==429)&&!Objects.toString(e.getReason(),"").contains("Idempotency");
     if(!busy||System.currentTimeMillis()>giveUp){fail(result.getResultId(),"SUBMIT_REJECTED");return;}
     heartbeat.run();sleeper.sleep(BUSY_RETRY_MILLIS);
    }
   }
   turnId=turn.id();
   records.update("UPDATE AssistantEvaluationResultEntity r SET r.status='SUBMITTED',r.sessionId=?1,r.turnId=?2 WHERE r.resultId=?3",turn.session(),turnId,result.getResultId());
  }
  var turn=db.turn(turnId);
  while(!TERMINAL_TURN.contains(turn.status())){
   if(System.currentTimeMillis()>turn.deadline()+60_000){fail(result.getResultId(),"TIMED_OUT");return;}
   heartbeat.run();sleeper.sleep(POLL_MILLIS);turn=db.turn(turnId);
  }
  grade(result.getResultId(),spec,turn);
 }
 /** Deterministic checks against the completed turn; a failed or canceled turn never passes. */
 void grade(String resultId,JsonNode spec,AssistantPersistence.Turn turn)throws IOException{
  var entity=records.find(AssistantTurnEntity.class,turn.id());Long latency=entity==null?null:entity.updatedAt-entity.createdAt;
  if(!"COMPLETED".equals(turn.status())){
   records.update("UPDATE AssistantEvaluationResultEntity r SET r.status='FAILED',r.errorCode=?1,r.autoPassed=FALSE,r.tokens=?2,r.costMicros=?3,r.latencyMs=?4 WHERE r.resultId=?5",
     turn.error()==null?turn.status():turn.error(),turn.tokens(),turn.cost(),latency,resultId);
   return;
  }
  var state=db.state(turn);String answer=normalize(state.answer);
  Set<String> used=new HashSet<>();state.evidence.forEach(e->used.add(e.path("name").asText()));
  List<Map<String,Object>> checks=new ArrayList<>();
  checks.add(check("Gave an answer",!answer.isBlank(),null));
  spec.path("require_tools").forEach(t->checks.add(check("Used "+t.asText(),used.contains(t.asText()),used.isEmpty()?"no tools used":"used "+String.join(", ",new TreeSet<>(used)))));
  var any=texts(spec.path("require_any_text"));
  if(!any.isEmpty())checks.add(check("Mentions one of: "+String.join(" / ",any),any.stream().anyMatch(t->matches(answer,t)),null));
  for(String required:texts(spec.path("require_all_text")))checks.add(check("Mentions "+required,matches(answer,required),null));
  if(spec.path("category").asText().startsWith("DECLINE")){var changes=used.stream().filter(t->!READ_TOOL.matcher(t).matches()).toList();checks.add(check("Used only read-only tools",changes.isEmpty(),changes.isEmpty()?null:"used "+String.join(", ",changes)));}
  var found=texts(spec.path("forbid_text")).stream().filter(t->matches(answer,t)).toList();
  checks.add(check("No false or unsafe claims",found.isEmpty(),found.isEmpty()?null:"found: "+String.join(", ",found)));
  boolean passed=checks.stream().allMatch(c->Boolean.TRUE.equals(c.get("passed")));
  records.update("UPDATE AssistantEvaluationResultEntity r SET r.status='COMPLETED',r.checksJson=?1,r.autoPassed=?2,r.tokens=?3,r.costMicros=?4,r.latencyMs=?5 WHERE r.resultId=?6",
    RuleDefinitionHistory.encode(checks),passed,turn.tokens(),turn.cost(),latency,resultId);
 }
 private static List<String> texts(JsonNode node){List<String> out=new ArrayList<>();node.forEach(v->out.add(v.asText().startsWith("re:")?v.asText():v.asText().toLowerCase(Locale.ROOT)));return out;}
 /** Lower case with curly apostrophes straightened, so "can’t" matches "can't". */
 static String normalize(String answer){return Objects.toString(answer,"").replace('\u2019','\'').replace('\u2018','\'').toLowerCase(Locale.ROOT);}
 /**
  * "re:" entries are case-insensitive regular expressions; a bare number matches only as a whole
  * number (so rule id 7 is not found in "17" or a date); anything else is a plain substring.
  */
 static boolean matches(String answer,String expected){
  if(expected.startsWith("re:"))return java.util.regex.Pattern.compile(expected.substring(3),java.util.regex.Pattern.CASE_INSENSITIVE).matcher(answer).find();
  if(expected.matches("\\d+"))return java.util.regex.Pattern.compile("(?<![\\w.])"+expected+"(?![\\w])").matcher(answer).find();
  return answer.contains(expected);
 }
 private static Map<String,Object> check(String name,boolean passed,String detail){Map<String,Object> c=new LinkedHashMap<>();c.put("check",name);c.put("passed",passed);c.put("detail",detail);return c;}
 private void fail(String resultId,String code){records.update("UPDATE AssistantEvaluationResultEntity r SET r.status='FAILED',r.errorCode=?1,r.autoPassed=FALSE WHERE r.resultId=?2",code,resultId);}
 private void failRemaining(String runId,String code){records.update("UPDATE AssistantEvaluationResultEntity r SET r.status='FAILED',r.errorCode=?1,r.autoPassed=FALSE WHERE r.runId=?2 AND r.status IN ('PENDING','SUBMITTED')",code,runId);}
 private void touch(String runId,String status){records.update("UPDATE AssistantEvaluationRunEntity r SET r.status=?1,r.updatedAt=?2 WHERE r.runId=?3 AND r.status IN ('QUEUED','RUNNING')",status,System.currentTimeMillis(),runId);}
 void finishRun(String runId,String status){long now=System.currentTimeMillis();records.update("UPDATE AssistantEvaluationRunEntity r SET r.status=?1,r.updatedAt=?2,r.finishedAt=?2 WHERE r.runId=?3 AND r.status IN ('QUEUED','RUNNING')",status,now,runId);}

 /** An engineer's 1–5 judgment of one answer, with an optional short note. */
 @Transactional
 public void score(String resultId,int score,String note,long version,String actor){
  access.require(actor,"Assistant Admin");
  if(score<1||score>5)throw new IllegalArgumentException("Score must be 1–5");
  String text=note==null?null:AssistantText.bounded(note.trim(),MAX_NOTE);
  if(records.update("UPDATE AssistantEvaluationResultEntity r SET r.score=?1,r.note=?2,r.reviewer=?3,r.scoredAt=?4,r.version=r.version+1 WHERE r.resultId=?5 AND r.version=?6 AND r.status IN ('COMPLETED','FAILED')",
    score,text,actor,System.currentTimeMillis(),AssistantPersistence.uuid(resultId),version)!=1)throw new ResponseStatusException(HttpStatus.CONFLICT,"Result changed or is not finished; reload");
 }
 @Transactional(readOnly=true)
 public List<Map<String,Object>> runs(String actor){
  access.require(actor,"Assistant Admin");
  return records.list(AssistantEvaluationRunEntity.class,"SELECT r FROM AssistantEvaluationRunEntity r ORDER BY r.createdAt DESC",0,10).stream().map(this::summary).toList();
 }
 @Transactional(readOnly=true)
 public Map<String,Object> get(String runId,String actor){
  access.require(actor,"Assistant Admin");
  var run=records.find(AssistantEvaluationRunEntity.class,AssistantPersistence.uuid(runId));
  if(run==null)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Evaluation not found");
  var view=summary(run);
  view.put("results",results(runId).stream().map(r->{
   Map<String,Object> v=new LinkedHashMap<>();
   v.put("id",r.getResultId());v.put("case_id",r.getCaseId());v.put("category",r.getCategory());v.put("status",r.getStatus());v.put("error",r.getErrorCode());
   v.put("session_id",r.getSessionId());v.put("auto_passed",r.getAutoPassed());v.put("checks",r.getChecksJson()==null?List.of():decode(r.getChecksJson()));
   v.put("tokens",r.getTokens());v.put("cost_micros",r.getCostMicros());v.put("latency_ms",r.getLatencyMs());
   v.put("score",r.getScore());v.put("note",r.getNote());v.put("reviewer",r.getReviewer());v.put("version",r.getVersion());
   try{v.put("prompt",AssistantState.mapper().readTree(r.getSpecJson()).path("prompt").asText());}catch(IOException e){v.put("prompt",null);}
   return v;}).toList());
  return view;
 }
 private List<AssistantEvaluationResultEntity> results(String runId){
  return records.list(AssistantEvaluationResultEntity.class,"SELECT r FROM AssistantEvaluationResultEntity r WHERE r.runId=?1 ORDER BY r.position",0,MAX_CASES,runId);
 }
 /**
  * The activation recommendation: every question answered, every automatic check passed, every
  * answer scored, average score at least 4 and none below 3. Enabling chat stays a human decision.
  */
 Map<String,Object> summary(AssistantEvaluationRunEntity run){
  var results=results(run.getRunId());
  long completed=results.stream().filter(r->"COMPLETED".equals(r.getStatus())).count(),passed=results.stream().filter(r->Boolean.TRUE.equals(r.getAutoPassed())).count();
  var scores=results.stream().map(AssistantEvaluationResultEntity::getScore).filter(Objects::nonNull).toList();
  double mean=scores.stream().mapToInt(Integer::intValue).average().orElse(0);int min=scores.stream().mapToInt(Integer::intValue).min().orElse(0);
  List<String> gaps=new ArrayList<>();
  String stopReason=stopReason(run,results);
  if(stopReason!=null)gaps.add(BUDGET_STOP.equals(stopReason)?"run stopped: daily AI budget reached":"run stopped: no question was answered");
  else if(!"DONE".equals(run.getStatus()))gaps.add("run not finished");
  if(completed<results.size())gaps.add((results.size()-completed)+" questions not answered");
  if(passed<results.size())gaps.add((results.size()-passed)+" automatic checks failed");
  if(scores.size()<results.size())gaps.add((results.size()-scores.size())+" answers not scored");
  // Separation of duties: the person who ran the evaluation does not also approve it.
  if(results.stream().anyMatch(r->run.getRequestedBy().equals(r.getReviewer())))gaps.add("answers must be scored by someone other than "+run.getRequestedBy());
  if(!scores.isEmpty()&&mean<4)gaps.add(String.format(Locale.ROOT,"average score %.1f is below 4",mean));
  if(!scores.isEmpty()&&min<3)gaps.add("an answer scored below 3");
  Map<String,Object> v=new LinkedHashMap<>();
  v.put("id",run.getRunId());v.put("cases_version",run.getCasesVersion());v.put("requested_by",run.getRequestedBy());v.put("model",run.getModel());v.put("effort",run.getEffort());
  v.put("status",run.getStatus());v.put("created_at",run.getCreatedAt());v.put("finished_at",run.getFinishedAt());v.put("questions",results.size());
  v.put("answered",completed);v.put("checks_passed",passed);v.put("scored",scores.size());v.put("average_score",scores.isEmpty()?null:Math.round(mean*10)/10.0);
  v.put("total_cost_micros",results.stream().mapToLong(AssistantEvaluationResultEntity::getCostMicros).sum());
  v.put("stop_reason",stopReason);
  v.put("recommendation",gaps.isEmpty()?"READY":"NOT_READY");v.put("gaps",gaps);
  return v;
 }
 /**
  * Why a finished run answered nothing: a run stopped at the budget, or an older "DONE" run whose
  * every question failed for the same reason. Null when anything was answered or it is still running.
  */
 static String stopReason(AssistantEvaluationRunEntity run,List<AssistantEvaluationResultEntity> results){
  if(!Set.of("DONE","STOPPED").contains(run.getStatus())||results.isEmpty())return null;
  if(results.stream().anyMatch(r->!"FAILED".equals(r.getStatus())))return null;
  var codes=results.stream().map(AssistantEvaluationResultEntity::getErrorCode).filter(Objects::nonNull).distinct().toList();
  return codes.size()==1?codes.getFirst():"STOPPED".equals(run.getStatus())?BUDGET_STOP:null;
 }
 private static List<Map<String,Object>> decode(String json){
  try{return AssistantState.mapper().convertValue(AssistantState.mapper().readTree(json),new com.fasterxml.jackson.core.type.TypeReference<List<Map<String,Object>>>(){});}
  catch(IOException e){LOG.warn("Unreadable evaluation checks");return List.of();}
 }
}
