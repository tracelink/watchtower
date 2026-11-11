package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.assessment.*;
import com.tracelink.appsec.watchtower.core.assistant.batch.*;
import com.tracelink.appsec.watchtower.core.assistant.features.StructuredFeatureCall;
import com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService;
import com.tracelink.appsec.watchtower.core.job.*;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/** S4: advice on up to 40 findings as a resumable background job; secrets never sent; nothing judged. */
class AssistantBatchTriageTest {
 static final Set<String> GRANTS=Set.of("Assistant Use","Scan Results View","Repository Settings View","Assistant Source Read");
 static final String VALID="{\"verdict\":\"LIKELY_FALSE_POSITIVE\",\"criteria\":{"
  +"\"input_reaches_sink\":{\"answer\":\"yes\",\"reason\":\"The request parameter reaches the write on line 88.\"},"
  +"\"sanitized\":{\"answer\":\"yes\",\"reason\":\"Encode.forHtml escapes it on line 86.\"},"
  +"\"test_or_generated_code\":{\"answer\":\"no\",\"reason\":\"Production controller code.\"},"
  +"\"matches_rule_intent\":{\"answer\":\"yes\",\"reason\":\"The rule targets unescaped HTML output.\"}},\"cited_lines\":[81,86,88],\"knowledge_ids\":[]}";
 @TempDir Path dir;AssistantFixture fx;AssessmentEvidence evidence;FindingAssessmentService assessments;BatchTriageService triage;AssistantSecretFindings secrets;AsyncJobService jobService;
 final AtomicBoolean keyConfigured=new AtomicBoolean(true);final AtomicInteger modelCalls=new AtomicInteger();final List<String> modelInputs=new ArrayList<>();final List<String> enqueued=new ArrayList<>();

 @BeforeEach @SuppressWarnings("unchecked") void setup()throws Exception{
  fx=new AssistantFixture(dir,GRANTS);
  fx.configure(c->AssistantFixture.slice(c,"batchTriage",true,300_000,300_000));
  fx.database.seedPr(1,1);
  // The in-memory test schema rejects every severity on this table; the real schema (Flyway) does not, so the check is dropped here.
  for(var name:fx.database.jdbc.queryForList("SELECT CONSTRAINT_NAME FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE CONSTRAINT_TYPE='CHECK' AND TABLE_NAME='pull_request_violations'",String.class))fx.database.jdbc.execute("ALTER TABLE pull_request_violations DROP CONSTRAINT \""+name+"\"");
  secrets=mock(AssistantSecretFindings.class);when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(),Set.of("private-key"),Set.of("betterleaks")));
  evidence=mock(AssessmentEvidence.class);var repo=mock(RepositoryEntity.class);when(repo.getId()).thenReturn(42L);
  when(evidence.locate(eq("pull_request"),eq(1L),anyString())).thenAnswer(i->new FindingLocator.Located("pull_request",1,i.getArgument(2),FindingFeedbackService.occurrenceKey("pull_request",1,i.getArgument(2)),7L,"a".repeat(64),repo,"c".repeat(40),"src/A.java",88,false,null));
  when(evidence.gather(anyString(),any())).thenAnswer(i->new AssessmentEvidence.Gathered(i.getArgument(1),null,"{\"code_window\":[]}",48,128,Set.of()));
  var keys=R1Database.keys(keyConfigured);
  FindingAssessmentService.Provider provider=request->{modelCalls.incrementAndGet();modelInputs.add(request.input());return new OpenAiLlmClient.StructuredReply(VALID,false,"completed",1000,300,true);};
  var exposures=new FindingAiExposures(fx.database.repository(FindingAiExposureRepository.class),fx.database.tx);
  assessments=new FindingAssessmentService(new FindingAssessmentService.Services(evidence,fx.settings,keys,fx.access,fx.budgets),fx.database.repository(FindingAssessmentRepository.class),fx.database.repository(FindingAssessmentViewRepository.class),exposures,fx.database.records,fx.database.tx,provider,Clock.systemUTC());
  jobService=mock(AsyncJobService.class);when(jobService.enqueue(any(),anyString(),anyString(),anyString())).thenAnswer(i->{enqueued.add(i.getArgument(1));return Optional.of(new AsyncJobEntity());});
  ObjectProvider<AsyncJobService> jobs=mock(ObjectProvider.class);when(jobs.getObject()).thenReturn(jobService);
  var calls=new StructuredFeatureCall(fx.settings,keys,fx.budgets,request->{throw new AssertionError("batch triage asks through assessments");});
  triage=new BatchTriageService(calls,fx.database.records,fx.database.repository(AiBatchRunRepository.class),fx.database.repository(AiBatchItemRepository.class),secrets,assessments,fx.database.repository(FindingAssessmentRepository.class),fx.access,fx.settings,fx.budgets,exposures,mock(RepoScanRepository.class),mock(RepoScanReportService.class),jobs,fx.database.tx);
 }
 @AfterEach void close(){fx.close();}

 void finding(String rule,String module,RulePriority severity){
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->{
   var v=new PullRequestViolationEntity();v.setScan(fx.database.records.find(PullRequestScanEntity.class,1L));v.setViolationName(rule);v.setSeverity(severity);v.setFileName("src/A.java");v.setLineNum(1);
   // A finding from before rule identities were recorded has none at all.
   if(module!=null)v.setRuleIdentity(new RuleExecutionIdentity(null,module,"a".repeat(64),null,null));fx.database.records.insert(v);
  });
 }
 @SuppressWarnings("unchecked") List<Map<String,Object>> items(Map<String,Object> view){return (List<Map<String,Object>>)view.get("items");}
 String runId(){return fx.database.jdbc.queryForObject("SELECT run_id FROM ai_batch_run",String.class);}

 @Test void theMostSevereFortyAreChosenAndSecretFindingsAreMarkedBlockedNotSent()throws Exception{
  for(int i=0;i<30;i++)finding("low-"+i,"PMD",RulePriority.LOW);
  for(int i=0;i<20;i++)finding("high-"+i,"PMD",RulePriority.HIGH);
  finding("private-key","Betterleaks",RulePriority.HIGH);
  var view=triage.start("alice","pull_request",1);
  assertEquals("QUEUED",view.get("state"));assertEquals(40,view.get("total"));assertEquals(1,view.get("blocked"));assertEquals(List.of(runId()),enqueued);
  long high=fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM ai_batch_item i JOIN pull_request_violations v ON CAST(v.vio_entity_id AS VARCHAR)=i.finding_key WHERE v.severity='High'",Long.class);
  assertEquals(21,high,"all the high findings come first");
  assertEquals("BLOCKED_SECRET",fx.database.jdbc.queryForObject("SELECT i.status FROM ai_batch_item i JOIN pull_request_violations v ON CAST(v.vio_entity_id AS VARCHAR)=i.finding_key WHERE v.violation_name='private-key'",String.class));
  triage.run(runId(),n->{});
  assertEquals(39,modelCalls.get(),"the secret finding is never sent");
  assertTrue(modelInputs.stream().noneMatch(in->in.contains("private-key")));
 }
 @Test void aRunAssessesEachFindingOnceChargesItsOwnShareAndJudgesNothing()throws Exception{
  for(int i=0;i<3;i++)finding("rule-"+i,"PMD",RulePriority.MEDIUM);
  int judgments=fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback",Integer.class);
  triage.start("alice","pull_request",1);
  var progress=new ArrayList<String>();
  String outcome=triage.run(runId(),progress::add);
  assertEquals("DONE 3/3",outcome);assertEquals(List.of("1/3","2/3","3/3"),progress);assertEquals(3,modelCalls.get());
  var view=triage.view("alice","pull_request",1);
  assertEquals("DONE",view.get("state"));assertTrue(items(view).stream().allMatch(i->"DONE".equals(i.get("status"))&&"LIKELY_FALSE_POSITIVE".equals(i.get("verdict"))));
  assertTrue(fx.budgets.usedToday(AssistantFeature.BATCH_TRIAGE).get("tokens")>0);
  assertEquals(judgments,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback",Integer.class),"advice never records a true or false positive");
  assertEquals(3,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_ai_exposure WHERE viewer='alice'",Integer.class),"reading the verdicts counts as seen");
 }
 @Test void aSecondRunOfTheSameJobDoesNotPayAgain()throws Exception{
  for(int i=0;i<2;i++)finding("rule-"+i,"PMD",RulePriority.MEDIUM);
  triage.start("alice","pull_request",1);triage.run(runId(),n->{});
  int calls=modelCalls.get();long used=fx.budgets.usedToday(AssistantFeature.BATCH_TRIAGE).get("tokens");
  assertEquals("DONE 2/2",triage.run(runId(),n->{}),"another pod picking up the same job finds nothing left");
  assertEquals(calls,modelCalls.get());assertEquals(used,fx.budgets.usedToday(AssistantFeature.BATCH_TRIAGE).get("tokens"));
 }
 @Test void aRunStopsAtItsShareAndAskingAgainResumesTheRest()throws Exception{
  for(int i=0;i<4;i++)finding("rule-"+i,"PMD",RulePriority.MEDIUM);
  triage.start("alice","pull_request",1);
  // Enough for roughly two assessments.
  fx.configure(c->AssistantFixture.slice(c,"batchTriage",true,28_000,30_000));
  String first=triage.run(runId(),n->{});
  assertTrue(first.startsWith("PARTIAL_BUDGET"),first);int done=modelCalls.get();assertTrue(done>0&&done<4,"some, not all: "+done);
  assertEquals("PARTIAL_BUDGET",triage.view("alice","pull_request",1).get("state"));
  String limit=String.valueOf(triage.view("alice","pull_request",1).get("limit"));
  assertTrue(limit.contains("this feature's daily share")&&limit.contains("AI assistant settings"),limit);
  fx.configure(c->AssistantFixture.slice(c,"batchTriage",true,300_000,300_000));
  enqueued.clear();triage.start("alice","pull_request",1);
  assertEquals(List.of(runId()),enqueued,"the same run is queued again");
  String second=triage.run(runId(),n->{});assertEquals("DONE 4/4",second);assertEquals(4,modelCalls.get(),"only the rest were asked");
 }
 @Test void startingAgainWhileItIsQueuedOrRunningQueuesNothingNew()throws Exception{
  finding("rule","PMD",RulePriority.MEDIUM);
  triage.start("alice","pull_request",1);enqueued.clear();
  assertEquals("QUEUED",triage.start("bob","pull_request",1).get("state"));assertTrue(enqueued.isEmpty());
 }
 @Test void aFullShareIsRefusedBeforeAnythingIsChosenOrQueued()throws Exception{
  finding("rule","PMD",RulePriority.MEDIUM);
  fx.configure(c->AssistantFixture.slice(c,"batchTriage",true,500,500));
  assertEquals(429,assertThrows(ResponseStatusException.class,()->triage.start("alice","pull_request",1)).getStatusCode().value());
  assertEquals(0,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM ai_batch_run",Integer.class));assertTrue(enqueued.isEmpty());
 }
 @Test void theSwitchTheKeyAndTheGrantsAreCheckedAndAScanWithNothingToTriageIsExplained()throws Exception{
  assertThrows(IllegalArgumentException.class,()->triage.start("alice","pull_request",1),"no findings");
  finding("rule","PMD",RulePriority.MEDIUM);
  keyConfigured.set(false);assertEquals("NO_API_KEY",triage.start("alice","pull_request",1).get("state"));keyConfigured.set(true);
  fx.configure(c->AssistantFixture.slice(c,"batchTriage",false,300_000,300_000));assertEquals("OFF",triage.start("alice","pull_request",1).get("state"));
  doThrow(new AccessDeniedException("no")).when(fx.access).require("mallory","Assistant Source Read");
  assertThrows(AccessDeniedException.class,()->triage.start("mallory","pull_request",1));assertThrows(AccessDeniedException.class,()->triage.view("mallory","pull_request",1));
  fx.configure(c->AssistantFixture.slice(c,"batchTriage",true,300_000,300_000));
  assertThrows(IllegalArgumentException.class,()->triage.start("alice","upload",1));
 }
 @Test void aRunStopsIfTheRequestersAccessIsRevokedOrTheSwitchIsTurnedOff()throws Exception{
  for(int i=0;i<2;i++)finding("rule-"+i,"PMD",RulePriority.MEDIUM);
  triage.start("alice","pull_request",1);
  doThrow(new AccessDeniedException("revoked")).when(fx.access).require("alice","Scan Results View");
  assertTrue(triage.run(runId(),n->{}).startsWith("FAILED"));assertEquals(0,modelCalls.get(),"nothing is sent for someone who may no longer read it");
  reset(fx.access);when(fx.access.authorities(anyString())).thenReturn(GRANTS);
  fx.configure(c->AssistantFixture.slice(c,"batchTriage",false,300_000,300_000));
  assertTrue(triage.run(runId(),n->{}).startsWith("FAILED"));assertEquals(0,modelCalls.get());
 }
 @Test void aFindingTheEvidenceStageRefusesAsASecretIsMarkedBlockedAndNotCounted()throws Exception{
  finding("rule","PMD",RulePriority.MEDIUM);
  when(evidence.gather(anyString(),any())).thenAnswer(i->new AssessmentEvidence.Gathered((FindingLocator.Located)i.getArgument(1),"A secret was recorded on this line, so it is never sent to the AI.",null,0,0,Set.of(),true));
  triage.start("alice","pull_request",1);triage.run(runId(),n->{});
  assertEquals("BLOCKED_SECRET",items(triage.view("alice","pull_request",1)).getFirst().get("status"));assertEquals(0,modelCalls.get());
 }
 @Test void aRefusalThatOnlyMentionsSecretsInItsTextIsNotMarkedAsASecretFinding()throws Exception{
  finding("rule","PMD",RulePriority.MEDIUM);
  when(evidence.gather(anyString(),any())).thenAnswer(i->new AssessmentEvidence.Gathered((FindingLocator.Located)i.getArgument(1),"The source at the scanned commit could not be read or checked for secrets: unavailable",null,0,0,Set.of()));
  triage.start("alice","pull_request",1);triage.run(runId(),n->{});
  assertEquals("NO_EVIDENCE",items(triage.view("alice","pull_request",1)).getFirst().get("status"),"unreadable source is not a secret finding, and the model was never asked");assertEquals(0,modelCalls.get());
 }
 @Test void aFindingWithNoRecordedRuleIsWithheldButNotCalledASecret()throws Exception{
  finding("old-rule",null,RulePriority.MEDIUM);finding("private-key","Betterleaks",RulePriority.HIGH);finding("rule","PMD",RulePriority.LOW);
  var view=triage.start("alice","pull_request",1);
  assertEquals(3,view.get("total"));assertEquals(2,view.get("blocked"),"both are withheld and neither is asked about");
  var statuses=new HashMap<String,Object>();
  fx.database.jdbc.queryForList("SELECT v.violation_name AS n, i.status AS s FROM ai_batch_item i JOIN pull_request_violations v ON CAST(v.vio_entity_id AS VARCHAR)=i.finding_key").forEach(r->statuses.put((String)r.get("n"),r.get("s")));
  assertEquals("BLOCKED_UNKNOWN",statuses.get("old-rule"),"the rule behind it was never recorded");
  assertEquals("BLOCKED_SECRET",statuses.get("private-key"));assertEquals("PENDING",statuses.get("rule"));
  triage.run(runId(),n->{});assertEquals(1,modelCalls.get(),"only the known, non-secret finding is sent");
 }
}
