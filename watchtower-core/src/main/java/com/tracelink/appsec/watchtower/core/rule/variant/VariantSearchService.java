package com.tracelink.appsec.watchtower.core.rule.variant;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.tracelink.appsec.watchtower.core.assistant.AssistantAccess;
import com.tracelink.appsec.watchtower.core.assistant.AssistantSourceTools;
import com.tracelink.appsec.watchtower.core.feedback.MissedVulnerabilityService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.candidate.*;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.PinnedSource;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmBranch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.SourceDownloadLimits;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/**
 * Step 3 of R5.3: runs one exact rule definition (the rule's current one or a reviewed candidate
 * draft) over up to 25 chosen repositories, each pinned to a commit. Deterministic: the same
 * definition, engine and commit give the same locations. Results are "matches to review" — counts,
 * relative paths and lines only — and never touch normal findings, comments, blocking or health.
 */
@Service
public class VariantSearchService {
 public record Start(String caseId,Long ruleId,String candidateId,List<Long> repositoryIds) { }
 private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(VariantSearchService.class);
 static final int MAX_REPOSITORIES=25,MAX_ACTIVE=3,MAX_LISTED=50;
 static final long HEARTBEAT_SECONDS=30,CLEANUP_TTL_MILLIS=60*60*1000L;
 /** Download plus engine deadlines stay well under this, so an older claim belongs to a stopped worker. */
 static final long STALE_ENTRY_MILLIS=20*60*1000L;
 /** A search with no progress for this long lost its job (crash, lost message) and is failed. */
 static final long STALE_SEARCH_MILLIS=2*60*60*1000L;
 private static final String LOCK="variant-searches",PREFIX="variant-";
 private static final Set<String> TERMINAL=Set.of("DONE","FAILED");
 private final LedgerRepository records;private final AssistantSourceTools source;private final AssistantAccess access;
 private final RuleService rules;private final RuleCandidateTester tester;private final MissedVulnerabilityService cases;
 // Lazy: AsyncJobService collects every job handler, including this service's own job.
 private final ObjectProvider<AsyncJobService> jobs;private final Path directory;private final TransactionTemplate separate;
 private final ScheduledExecutorService heartbeats=Executors.newSingleThreadScheduledExecutor();
 public VariantSearchService(LedgerRepository records,AssistantSourceTools source,AssistantAccess access,RuleService rules,RuleCandidateTester tester,
   MissedVulnerabilityService cases,ObjectProvider<AsyncJobService> jobs,PlatformTransactionManager transactions,@Value("${watchtower.rule-testing.search-directory:${java.io.tmpdir}/watchtower-variant-search}")String directory){
  this.records=records;this.source=source;this.access=access;this.rules=rules;this.tester=tester;this.cases=cases;this.jobs=jobs;this.directory=Path.of(directory);
  separate=new TransactionTemplate(transactions);separate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
 }
 private void requireView(String actor){for(String grant:AssistantSourceTools.GRANTS)access.require(actor,grant);}
 private void requireRun(String actor){requireView(actor);access.require(actor,"Rule Modify");}

 @Transactional
 public String start(Start start,String actor){
  requireRun(actor);
  var ids=start.repositoryIds()==null?List.<Long>of():start.repositoryIds();
  if(ids.isEmpty()||ids.size()>MAX_REPOSITORIES||new HashSet<>(ids).size()!=ids.size())throw new IllegalArgumentException("Choose 1–25 different repositories");
  var missed=start.caseId()==null?null:cases.find(start.caseId(),actor);
  Long ruleId=start.ruleId()!=null?start.ruleId():missed==null?null:missed.ruleId;
  if(ruleId==null)throw new IllegalArgumentException("Choose the rule to search with");
  RuleDto rule;try{rule=rules.getRule(ruleId).toDto();}catch(Exception e){throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Rule not found");}
  String definition=start.candidateId()==null?RuleDefinitionHistory.definition(rule):candidateDefinition(start.candidateId(),ruleId);
  String module=rule.getModule().toLowerCase(Locale.ROOT);
  try{tester.requireRuntime(module);}catch(IllegalStateException e){throw new ResponseStatusException(HttpStatus.CONFLICT,"This rule's engine is unavailable");}
  if(!tester.available())throw new ResponseStatusException(HttpStatus.CONFLICT,"Rule testing is disabled or unavailable");
  List<RepositoryEntity> targets=new ArrayList<>();
  for(long id:ids){
   var target=source.target(actor,id);
   if(target.api()==null||!(target.repository().getScanType() instanceof CodeScanType))throw new IllegalArgumentException("Only code repositories with a live integration can be searched");
   targets.add(target.repository());
  }
  records.lockScope(LOCK);
  if(records.scalar(Long.class,"SELECT COUNT(s) FROM VariantSearchEntity s WHERE s.status IN ('QUEUED','RUNNING')")>=MAX_ACTIVE)
   throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"Three searches are already running; try again when one finishes");
  String id=UUID.randomUUID().toString();
  records.insert(new VariantSearchEntity(id,missed==null?null:missed.caseId,ruleId,start.candidateId(),module,rule.getRuleDesignation().name(),RuleDefinitionHistory.hash(definition),definition,actor,System.currentTimeMillis()));
  for(int i=0;i<targets.size();i++){var r=targets.get(i);records.insert(new VariantSearchRepositoryEntity(UUID.randomUUID().toString(),id,i,r.getId(),r.getRepoName(),r.getApiLabel()));}
  // Queue only after commit, so a worker can never claim a search that rolled back. The committed
  // transaction cannot take more writes, so the job row and any failure mark use a new one.
  TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){@Override public void afterCommit(){
   try{separate.executeWithoutResult(tx->{if(jobs.getObject().enqueue(AsyncJobType.VARIANT_SEARCH,id,"variant-search:"+id,actor).isEmpty())fail(id,"QUEUE_UNAVAILABLE");});}
   catch(RuntimeException e){LOG.warn("Variant search {} could not be queued",id,e);fail(id,"QUEUE_UNAVAILABLE");}
  }});
  return id;
 }
 private String candidateDefinition(String candidateId,long ruleId){
  if(!candidateId.matches("[a-f0-9-]{36}"))throw new IllegalArgumentException("Invalid candidate");
  var rows=records.maps("SELECT c.ruleId AS rule_id,c.definitionJson AS definition_json,c.status AS status FROM RuleCandidateEntity c WHERE c.candidateId=?1",0,1,candidateId);
  if(rows.isEmpty()||((Number)rows.getFirst().get("rule_id")).longValue()!=ruleId)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Candidate not found for this rule");
  if("REJECTED".equals(rows.getFirst().get("status")))throw new IllegalArgumentException("Rejected drafts cannot be searched");
  return (String)rows.getFirst().get("definition_json");
 }

 /** Job body. Re-runnable: finished repositories are skipped, so a re-claimed job resumes. */
 public void run(String searchId,Consumer<String> progress){
  var search=records.find(VariantSearchEntity.class,searchId);
  if(search==null||TERMINAL.contains(search.getStatus()))return;
  records.update("UPDATE VariantSearchEntity s SET s.status='RUNNING',s.updatedAt=?1 WHERE s.searchId=?2 AND s.status='QUEUED'",System.currentTimeMillis(),searchId);
  var entries=records.list(VariantSearchRepositoryEntity.class,"SELECT e FROM VariantSearchRepositoryEntity e WHERE e.searchId=?1 ORDER BY e.position",0,MAX_REPOSITORIES,searchId);
  for(int i=0;i<entries.size();i++){
   var entry=entries.get(i);if(!Set.of("PENDING","RUNNING").contains(entry.getStatus()))continue;
   // Atomic claim: a worker re-claimed after a stall cannot search the same repository twice.
   long now=System.currentTimeMillis();
   if(records.update("UPDATE VariantSearchRepositoryEntity e SET e.status='RUNNING',e.claimedAt=?1 WHERE e.entryId=?2 AND (e.status='PENDING' OR (e.status='RUNNING' AND e.claimedAt<?3))",now,entry.getEntryId(),now-STALE_ENTRY_MILLIS)!=1)continue;
   String note="Searching repository "+(i+1)+" of "+entries.size();progress.accept(note);
   ScheduledFuture<?> beat=heartbeats.scheduleAtFixedRate(()->{try{progress.accept(note);touch(searchId);}catch(RuntimeException e){LOG.warn("Variant search heartbeat failed; the job lease may expire");}},HEARTBEAT_SECONDS,HEARTBEAT_SECONDS,TimeUnit.SECONDS);
   try{
    try{requireRun(search.getRequestedBy());}catch(AccessDeniedException e){fail(searchId,"ACCESS_REVOKED");return;}
    try{tester.requireRuntime(search.getModule());}catch(RuntimeException e){fail(searchId,"ENGINE_UNAVAILABLE");return;}
    searchOne(search,entry);
   }finally{beat.cancel(false);}
  }
  if(records.scalar(Long.class,"SELECT COUNT(e) FROM VariantSearchRepositoryEntity e WHERE e.searchId=?1 AND e.status IN ('PENDING','RUNNING')",searchId)==0)
   records.update("UPDATE VariantSearchEntity s SET s.status='DONE',s.finishedAt=?1,s.updatedAt=?1 WHERE s.searchId=?2 AND s.status='RUNNING'",System.currentTimeMillis(),searchId);
 }
 private void touch(String searchId){records.update("UPDATE VariantSearchEntity s SET s.updatedAt=?1 WHERE s.searchId=?2",System.currentTimeMillis(),searchId);}
 /** Fails searches whose job stopped making progress, so they neither hang nor hold the active limit. */
 @Scheduled(fixedDelayString="${watchtower.rule-testing.variant-reaper-delay-ms:300000}")
 @SchedulerLock(name="variantSearchReaper",lockAtMostFor="PT5M")
 public void reapStale(){
  for(var id:records.maps("SELECT s.searchId AS id FROM VariantSearchEntity s WHERE s.status IN ('QUEUED','RUNNING') AND s.updatedAt<?1",0,100,System.currentTimeMillis()-STALE_SEARCH_MILLIS))
   fail((String)id.get("id"),"TIMED_OUT");
 }
 private void searchOne(VariantSearchEntity search,VariantSearchRepositoryEntity entry){
  AssistantSourceTools.Target target;
  try{target=source.target(search.getRequestedBy(),entry.getRepositoryId());}catch(AccessDeniedException e){finish(entry,"SKIPPED","REPOSITORY_UNAVAILABLE",null);return;}
  if(target.api()==null){finish(entry,"SKIPPED","REPOSITORY_UNAVAILABLE",null);return;}
  String commit=entry.getCommitHash();
  if(commit==null){
   String branchName=target.repository().getDefaultBranch();
   Optional<ScmBranch> branch=branchName==null?Optional.empty():target.api().getBranch(entry.getRepositoryName(),branchName);
   if(branch.isEmpty()||branch.get().commitHash()==null||!branch.get().commitHash().matches("[a-f0-9]{40}")){finish(entry,"SKIPPED","BRANCH_UNAVAILABLE",null);return;}
   commit=branch.get().commitHash();
   // Pin before downloading: the commit shown with the result is exactly what was searched.
   records.update("UPDATE VariantSearchRepositoryEntity e SET e.commitHash=?1 WHERE e.entryId=?2",commit,entry.getEntryId());
  }
  try{
   var result=PinnedSource.open(target.api(),entry.getRepositoryName(),commit,directory,PREFIX,SourceDownloadLimits.SCAN,
     root->tester.search(new RuleTestSuite.SearchRequest(search.getModule(),search.getDesignation(),search.getDefinitionJson(),root.toString())));
   finish(entry,result.status(),null,result);
  }catch(IOException e){LOG.warn("Variant search could not download repository {}",entry.getRepositoryName());finish(entry,"SKIPPED","SOURCE_UNAVAILABLE",null);}
  catch(RuntimeException e){LOG.warn("Variant search engine failed for repository {}",entry.getRepositoryName());finish(entry,"FAILED","ENGINE_FAILED",null);}
 }
 private void finish(VariantSearchRepositoryEntity entry,String status,String error,RuleTestSuite.SearchResult result){
  String locations=result==null?null:RuleDefinitionHistory.encode(result.matches());
  String identity=result==null||result.identity()==null?null:RuleDefinitionHistory.hash(result.identity());
  long now=System.currentTimeMillis();
  records.update("UPDATE VariantSearchRepositoryEntity e SET e.status=?1,e.errorCode=?2,e.matchCount=?3,e.truncated=?4,e.locationsJson=?5,e.engineIdentity=?6,e.finishedAt=?7 WHERE e.entryId=?8",
    status,error,result==null?0:result.matches().size(),result!=null&&result.truncated(),locations,identity,now,entry.getEntryId());
  touch(entry.getSearchId());
 }
 /** Marks a search failed; every repository not yet searched is reported as skipped with the reason. */
 void fail(String searchId,String error){
  long now=System.currentTimeMillis();
  records.update("UPDATE VariantSearchRepositoryEntity e SET e.status='SKIPPED',e.errorCode=?1,e.finishedAt=?2 WHERE e.searchId=?3 AND e.status IN ('PENDING','RUNNING')",error,now,searchId);
  records.update("UPDATE VariantSearchEntity s SET s.status='FAILED',s.finishedAt=?1,s.updatedAt=?1 WHERE s.searchId=?2 AND s.status IN ('QUEUED','RUNNING')",now,searchId);
 }

 public Map<String,Object> get(String searchId,String actor){
  requireView(actor);
  if(searchId==null||!searchId.matches("[a-f0-9-]{36}"))throw new IllegalArgumentException("Invalid search");
  var search=records.find(VariantSearchEntity.class,searchId);
  if(search==null)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Search not found");
  // A search started from a case is visible to whoever may see that case.
  if(search.getCaseId()!=null)cases.find(search.getCaseId(),actor);
  var view=summary(search);
  view.put("repositories",records.list(VariantSearchRepositoryEntity.class,"SELECT e FROM VariantSearchRepositoryEntity e WHERE e.searchId=?1 ORDER BY e.position",0,MAX_REPOSITORIES,searchId).stream().map(e->{
   Map<String,Object> r=new LinkedHashMap<>();r.put("repository_id",e.getRepositoryId());r.put("repository",e.getRepositoryName());r.put("commit",e.getCommitHash());
   r.put("status",e.getStatus());r.put("error",e.getErrorCode());r.put("engine_identity",e.getEngineIdentity());r.put("matches",e.getMatchCount());r.put("truncated",e.isTruncated());
   r.put("locations",e.getLocationsJson()==null?List.of():decode(e.getLocationsJson()));return r;}).toList());
  return view;
 }
 public List<Map<String,Object>> forCase(String caseId,String actor){
  var missed=cases.find(caseId,actor);
  return records.list(VariantSearchEntity.class,"SELECT s FROM VariantSearchEntity s WHERE s.caseId=?1 ORDER BY s.createdAt DESC",0,20,missed.caseId).stream().map(this::summary).toList();
 }
 /** Enabled code repositories with a live integration, for the picker. */
 public List<Map<String,Object>> repositories(String query,String actor){
  requireView(actor);
  String q=query==null?"":query.trim().toLowerCase(Locale.ROOT);if(q.length()>100)throw new IllegalArgumentException("Search text too long");
  // '!' rather than a backslash: MySQL treats backslashes in string literals as escapes.
  String pattern="%"+q.replace("!","!!").replace("%","!%").replace("_","!_")+"%";
  List<Map<String,Object>> rows=new ArrayList<>();Map<String,Boolean> live=new HashMap<>();
  for(var r:records.list(RepositoryEntity.class,"SELECT r FROM RepositoryEntity r WHERE r.enabled=TRUE AND LOWER(r.repoName) LIKE ?1 ESCAPE '!' ORDER BY r.repoName",0,MAX_LISTED*2,pattern)){
   if(!(r.getScanType() instanceof CodeScanType))continue;
   // One integration check per label, not per repository.
   if(!live.computeIfAbsent(r.getApiLabel(),label->{try{return source.target(actor,r.getId()).api()!=null;}catch(AccessDeniedException e){return false;}}))continue;
   rows.add(Map.of("id",r.getId(),"name",r.getRepoName(),"integration",r.getApiLabel(),"default_branch",Objects.toString(r.getDefaultBranch(),"unknown")));
   if(rows.size()==MAX_LISTED)break;
  }
  return rows;
 }
 private Map<String,Object> summary(VariantSearchEntity s){
  Map<String,Object> v=new LinkedHashMap<>();
  v.put("id",s.getSearchId());v.put("case_id",s.getCaseId());v.put("rule_id",s.getRuleId());v.put("candidate_id",s.getCandidateId());v.put("module",s.getModule());
  v.put("definition_hash",s.getDefinitionHash());v.put("requested_by",s.getRequestedBy());v.put("status",s.getStatus());v.put("created_at",s.getCreatedAt());v.put("finished_at",s.getFinishedAt());
  v.put("total_matches",records.scalar(Long.class,"SELECT COALESCE(SUM(e.matchCount),0) FROM VariantSearchRepositoryEntity e WHERE e.searchId=?1",s.getSearchId()));
  return v;
 }
 private static List<Map<String,Object>> decode(String json){
  try{return RuleDefinitionHistory.JSON.readValue(json,new TypeReference<List<Map<String,Object>>>(){});}
  catch(IOException e){LOG.warn("Unreadable variant search locations");return List.of();}
 }
 @Scheduled(fixedDelayString="${watchtower.rule-testing.cleanup-delay-ms:60000}")
 public void cleanup(){
  try{PinnedSource.sweep(directory,PREFIX,CLEANUP_TTL_MILLIS);}catch(IOException e){LOG.warn("Variant search temporary cleanup failed; retrying on the next tick");}
 }
 @PreDestroy public void close(){heartbeats.shutdownNow();}
}
