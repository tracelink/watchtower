package com.tracelink.appsec.watchtower.core.assistant.batch;

import java.util.*;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.assistant.assessment.*;
import com.tracelink.appsec.watchtower.core.assistant.features.StructuredFeatureCall;
import com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/**
 * Advice on up to 40 findings of one scan, run as a background job that any pod can pick up. Secret
 * findings are marked blocked and never sent. Each finding is one item, so a restarted or duplicated job
 * resumes without paying twice, and the run stops, not fails, when its daily share is used up. Nothing
 * here records a judgment: the verdicts are advice the person reads, and reading them counts as seen.
 */
@Service
public class BatchTriageService {
 private static final Logger LOG=LoggerFactory.getLogger(BatchTriageService.class);
 public static final int MAX_FINDINGS=40;
 static final int MAX_ROWS=5000;
 private final StructuredFeatureCall calls;private final LedgerRepository records;private final AiBatchRunRepository runs;private final AiBatchItemRepository items;
 private final AssistantSecretFindings secrets;private final FindingAssessmentService assessments;private final FindingAssessmentRepository assessmentRows;
 private final AssistantAccess access;private final AssistantSettingsService settings;private final AssistantBudgetService budgets;private final FindingAiExposures exposures;
 private final RepoScanRepository repoScans;private final RepoScanReportService reports;private final ObjectProvider<AsyncJobService> jobs;private final TransactionTemplate tx;
 public BatchTriageService(StructuredFeatureCall calls,LedgerRepository records,AiBatchRunRepository runs,AiBatchItemRepository items,AssistantSecretFindings secrets,
   FindingAssessmentService assessments,FindingAssessmentRepository assessmentRows,AssistantAccess access,AssistantSettingsService settings,AssistantBudgetService budgets,
   FindingAiExposures exposures,RepoScanRepository repoScans,RepoScanReportService reports,ObjectProvider<AsyncJobService> jobs,PlatformTransactionManager tm){
  this.calls=calls;this.records=records;this.runs=runs;this.items=items;this.secrets=secrets;this.assessments=assessments;this.assessmentRows=assessmentRows;this.access=access;
  this.settings=settings;this.budgets=budgets;this.exposures=exposures;this.repoScans=repoScans;this.reports=reports;this.jobs=jobs;this.tx=new TransactionTemplate(tm);
 }
 /** One finding of the scan, as chosen for the run. {@code unknown}: its rule was never recorded, so it cannot be told from a secret and is withheld without being called one. */
 record Candidate(String key,int priority,boolean secret,boolean unknown) {
  boolean withheld(){return secret||unknown;}
  String startStatus(){return secret?AiBatchItemEntity.BLOCKED_SECRET:unknown?AiBatchItemEntity.BLOCKED_UNKNOWN:AiBatchItemEntity.PENDING;}
 }

 private void requireAccess(String owner){access.require(owner,"Assistant Use");for(String grant:AssistantSourceTools.GRANTS)access.require(owner,grant);}

 /** Starts the triage of a scan, or returns the run already under way; asking again resumes a stopped run. */
 public Map<String,Object> start(String owner,String scanType,long scanId){
  requireAccess(owner);
  var ready=calls.readiness(AssistantFeature.BATCH_TRIAGE);
  if(!ready.ready())return Map.of("state",ready.problem(),"message",ready.message());
  var cfg=settings.get().settings();var model=cfg.model(cfg.defaultModel(),cfg.defaultEffort());
  // A full share is refused before anything is chosen or queued.
  if(!budgets.canAfford(owner,cfg,model,AssistantSettings.FindingAssessment.INPUT_TOKENS,AssistantSettings.FindingAssessment.OUTPUT_TOKENS,AssistantFeature.BATCH_TRIAGE))
   throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,AssistantBudgetService.limitMessage(AssistantFeature.BATCH_TRIAGE,budgets.shortfall(owner,cfg,model,AssistantSettings.FindingAssessment.INPUT_TOKENS,AssistantSettings.FindingAssessment.OUTPUT_TOKENS,AssistantFeature.BATCH_TRIAGE)));
  var existing=runs.findByScanTypeAndScanId(scanType,scanId).orElse(null);
  if(existing!=null&&(AiBatchRunEntity.QUEUED.equals(existing.getStatus())||AiBatchRunEntity.RUNNING.equals(existing.getStatus())))return view(owner,scanType,scanId);
  var run=existing!=null?requeue(existing,owner):create(owner,scanType,scanId);
  jobs.getObject().enqueue(AsyncJobType.AI_BATCH_TRIAGE,run.getRunId(),"ai-batch-triage:"+run.getRunId(),owner);
  return view(owner,scanType,scanId);
 }
 private AiBatchRunEntity requeue(AiBatchRunEntity run,String owner){
  return tx.execute(s->{run.setStatus(AiBatchRunEntity.QUEUED,null);run.setRequestedBy(owner);return runs.save(run);});
 }
 private AiBatchRunEntity create(String owner,String scanType,long scanId){
  var chosen=select(scanType,scanId);
  if(chosen.isEmpty())throw new IllegalArgumentException("This scan has no findings to triage.");
  String runId=UUID.randomUUID().toString();int blocked=(int)chosen.stream().filter(Candidate::withheld).count();
  return tx.execute(s->{
   var run=runs.save(new AiBatchRunEntity(runId,scanType,scanId,owner,chosen.size(),blocked,System.currentTimeMillis()));
   run.setDone(blocked);
   items.saveAll(chosen.stream().map(c->new AiBatchItemEntity(runId,c.key(),c.startStatus())).toList());
   return runs.save(run);
  });
 }

 /** The most severe findings, at most 40, with any finding that could be a secret marked so it is never sent. */
 List<Candidate> select(String scanType,long scanId){
  var secret=secrets.secretRules();List<Candidate> all=new ArrayList<>();
  switch(scanType==null?"":scanType){
   case "pull_request"->{
    var rows=records.maps("SELECT v.id AS id,v.severity AS severity,v.violationName AS name,v.ruleIdentity.module AS module,v.ruleIdentity.ruleId AS rule_id FROM PullRequestViolationEntity v WHERE v.scan.id=?1",0,MAX_ROWS+1,scanId);
    if(rows.size()>MAX_ROWS)throw new IllegalArgumentException("This scan has too many findings to triage.");
    for(var row:rows){
     Long ruleId=row.get("rule_id") instanceof Number n?n.longValue():null;
     boolean unknown=ruleId==null&&row.get("module")==null;
     boolean isSecret=secret.contains(ruleId,(String)row.get("module"),(String)row.get("name"));
     all.add(new Candidate(String.valueOf(row.get("id")),row.get("severity") instanceof RulePriority p?p.getPriority():RulePriority.INFORMATIONAL.getPriority(),isSecret,unknown&&!isSecret));
    }
   }
   case "repository"->{
    var scan=repoScans.findById(scanId).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Unknown scan"));
    var report=reports.getReport(scan).orElseThrow(()->new IllegalArgumentException("The scan report has expired."));
    for(var f:report.findings()){
     if(f.findingKey()==null)continue;var identity=f.ruleIdentity();
     boolean unknown=identity==null||identity.ruleId()==null&&identity.module()==null;
     boolean isSecret=Boolean.TRUE.equals(f.sensitive())||secret.contains(identity==null?null:identity.ruleId(),identity==null?null:identity.module(),f.rule());
     all.add(new Candidate(f.findingKey(),priorityOf(f.severity()),isSecret,unknown&&!isSecret));
    }
   }
   default->throw new IllegalArgumentException("Only pull request and repository scans can be triaged.");
  }
  all.sort(Comparator.comparingInt(Candidate::priority).thenComparing(Candidate::key));
  return List.copyOf(all.subList(0,Math.min(MAX_FINDINGS,all.size())));
 }
 private static int priorityOf(String severity){
  if(severity==null)return RulePriority.INFORMATIONAL.getPriority();
  var byName=RulePriority.priorityForName(severity);if(byName!=null)return byName.getPriority();
  try{return RulePriority.valueOf(severity.toUpperCase(Locale.ROOT).replace('-','_').replace(' ','_')).getPriority();}catch(IllegalArgumentException e){return RulePriority.INFORMATIONAL.getPriority();}
 }

 /** The job body: one finding at a time, resumable, stopping when the share runs out. */
 public String run(String runId,Consumer<String> progress){
  var run=runs.findById(runId).orElse(null);
  if(run==null)return "Unknown run";
  tx.executeWithoutResult(s->{run.setStatus(AiBatchRunEntity.RUNNING,null);runs.save(run);});
  String owner=run.getRequestedBy();String outcome=AiBatchRunEntity.DONE;
  for(var item:items.findByRunIdOrderByFindingKey(runId)){
   if(!AiBatchItemEntity.PENDING.equals(item.getStatus()))continue;
   try{
    requireAccess(owner);
    if(!calls.readiness(AssistantFeature.BATCH_TRIAGE).ready()){outcome=AiBatchRunEntity.FAILED;break;}
    var result=assessments.assessForBatch(owner,run.getScanType(),run.getScanId(),item.getFindingKey());
    record(run,item,result);
    progress.accept(run.getDone()+"/"+run.getTotal());
   }catch(AccessDeniedException e){outcome=AiBatchRunEntity.FAILED;break;}
   catch(ResponseStatusException e){outcome=e.getStatusCode().value()==429?AiBatchRunEntity.PARTIAL_BUDGET:AiBatchRunEntity.FAILED;break;}
   catch(RuntimeException e){LOG.warn("Batch triage {} stopped on one finding: {}",runId,e.getClass().getSimpleName());outcome=AiBatchRunEntity.FAILED;break;}
  }
  String finalOutcome=outcome;
  tx.executeWithoutResult(s->{var fresh=runs.findById(runId).orElseThrow();fresh.setStatus(finalOutcome,System.currentTimeMillis());runs.save(fresh);});
  return finalOutcome+" "+run.getDone()+"/"+run.getTotal();
 }
 private void record(AiBatchRunEntity run,AiBatchItemEntity item,Map<String,Object> result){
  String state=String.valueOf(result.get("state"));
  String status,assessment=null;
  if("ASSESSED".equals(state)){status=AiBatchItemEntity.DONE;assessment=String.valueOf(result.get("id"));}
  // The refusal says so explicitly; the wording of its message is never read.
  else if("secret".equals(result.get("blocked")))status=AiBatchItemEntity.BLOCKED_SECRET;
  // Nothing was sent to the model: say so, instead of calling it an answer the model failed to give
  else if("INSUFFICIENT_EVIDENCE".equals(state))status=AiBatchItemEntity.NO_EVIDENCE;
  else status=AiBatchItemEntity.NO_ANSWER;
  String finalStatus=status,finalAssessment=assessment;
  tx.executeWithoutResult(s->{
   item.finish(finalStatus,finalAssessment);items.save(item);
   run.setDone(run.getDone()+1);runs.save(run);
  });
 }

 /** Progress and the advice so far. Reading a verdict counts as having seen an AI opinion of that finding. */
 public Map<String,Object> view(String owner,String scanType,long scanId){
  requireAccess(owner);
  var run=runs.findByScanTypeAndScanId(scanType,scanId).orElse(null);
  if(run==null)return Map.of("state","NONE");
  var out=new ArrayList<Map<String,Object>>();var seen=new ArrayList<String>();
  for(var item:items.findByRunIdOrderByFindingKey(run.getRunId())){
   var row=new LinkedHashMap<String,Object>();row.put("key",item.getFindingKey());row.put("status",item.getStatus());
   if(item.getAssessmentId()!=null){
    assessmentRows.findById(item.getAssessmentId()).filter(a->FindingAssessmentEntity.ASSESSED.equals(a.getStatus())).ifPresent(a->{row.put("verdict",a.getVerdict());seen.add(a.getOccurrenceKey());});
   }
   out.add(row);
  }
  exposures.recordAll(seen,owner,FindingAiExposures.ASSESSMENT);
  var view=new LinkedHashMap<String,Object>();
  view.put("state",run.getStatus());view.put("total",run.getTotal());view.put("done",run.getDone());view.put("blocked",run.getBlocked());view.put("items",out);
  view.put("note","Advice only: a person makes every judgment. Seeing these verdicts leaves them out of the blind AI-vs-human number.");
  if(AiBatchRunEntity.PARTIAL_BUDGET.equals(run.getStatus())){
   // Say which limit stopped it: the feature's share, a person's tokens and the organization's are different fixes.
   try{
    var cfg=settings.get().settings();var model=cfg.model(cfg.defaultModel(),cfg.defaultEffort());
    String why=budgets.shortfall(owner,cfg,model,AssistantSettings.FindingAssessment.INPUT_TOKENS,AssistantSettings.FindingAssessment.OUTPUT_TOKENS,AssistantFeature.BATCH_TRIAGE);
    if(why!=null)view.put("limit",AssistantBudgetService.limitMessage(AssistantFeature.BATCH_TRIAGE,why));
   }catch(RuntimeException unavailable){/* the page falls back to its general wording */}
  }
  return view;
 }
}
