package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.features.*;
import com.tracelink.appsec.watchtower.core.job.*;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.*;

/** S3: the bypass summary and the failure diagnosis only advise, send no code, and never reach a secret. */
class AssistantFeatureServicesTest {
 static final Set<String> GRANTS=Set.of("Assistant Use","Scan Results View","PR Scan Bypass");
 @TempDir Path dir;AssistantFixture fx;AssistantSecretFindings secrets;StructuredFeatureCall calls;BypassSummaryService bypass;JobDiagnosisService diagnosis;AsyncJobRepository jobs;
 final List<OpenAiLlmClient.Structured> sent=new ArrayList<>();final Deque<OpenAiLlmClient.StructuredReply> replies=new ArrayDeque<>();final AtomicBoolean keyConfigured=new AtomicBoolean(true);

 static OpenAiLlmClient.StructuredReply reply(String text){return new OpenAiLlmClient.StructuredReply(text,false,"completed",1200,60,true);}
 @BeforeEach void setup()throws Exception{
  fx=new AssistantFixture(dir,GRANTS);
  fx.configure(c->{AssistantFixture.slice(c,"bypassSummary",true,200_000,200_000);AssistantFixture.slice(c,"jobDiagnosis",true,200_000,200_000);});
  secrets=mock(AssistantSecretFindings.class);when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(),Set.of("private-key"),Set.of("betterleaks")));
  calls=new StructuredFeatureCall(fx.settings,R1Database.keys(keyConfigured),fx.budgets,request->{sent.add(request);return replies.isEmpty()?reply("{\"risk_note\":\"Two High findings are covered; check the files before you decide.\"}"):replies.poll();});
  bypass=new BypassSummaryService(calls,fx.database.records,secrets,fx.access);
  jobs=fx.database.repository(AsyncJobRepository.class);diagnosis=new JobDiagnosisService(calls,jobs,fx.access);
  fx.database.seedPr(1,1);
 }
 @AfterEach void close(){fx.close();}

 long request(String reason,BypassReasonCode code){
  var r=new PullRequestBypassRequestEntity();r.setApiLabel("Bitbucket");r.setRepoName("wt-test");r.setPrId("58");r.setScanId(1);r.setRequestedBy("casey");r.setReason(reason);r.setCreatedAt(1);r.setReasonCode(code);
  return fx.database.records.insert(r).getId();
 }
 long save(AsyncJobEntity job){return new TransactionTemplate(fx.database.tx).execute(status->jobs.save(job).getId());}
 void blocking(String rule,String module,String file){
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->{
   var v=new PullRequestViolationEntity();v.setScan(fx.database.records.find(PullRequestScanEntity.class,1L));v.setViolationName(rule);v.setFileName(file);v.setLineNum(1);v.setBlocking(true);
   v.setRuleIdentity(new RuleExecutionIdentity(null,module,"a".repeat(64),null,null));fx.database.records.insert(v);
  });
 }

 @Test void aSummaryHasCountsFromTheScanAndOneSentenceFromTheModel(){
  blocking("ImmutableField","PMD","ImageSecurityReport.java");blocking("ImmutableField","PMD","ImageSecurityReport.java");blocking("UnusedPrivateField","PMD","Other.java");
  long id=request("Test fixtures with fake keys; tracked in SEC-123",BypassReasonCode.TEST_CODE);
  var summary=bypass.summarize("alice",id);
  assertEquals("OK",summary.get("state"));assertEquals("TEST_CODE",summary.get("reason_code"));assertEquals(3L,summary.get("total"));assertEquals(2,summary.get("files"));
  assertEquals("Two High findings are covered; check the files before you decide.",summary.get("risk_note"));
  assertEquals(1,sent.size());var input=sent.getFirst().input();
  assertTrue(input.contains("Test fixtures with fake keys"));assertTrue(input.contains("ImmutableField"));assertFalse(input.contains("ImageSecurityReport"),"file names are counted, never sent");
  assertTrue(sent.getFirst().instructions().contains("never say the request should be approved")||sent.getFirst().instructions().contains("Never say the request should be approved"));
  assertTrue(fx.budgets.usedToday(AssistantFeature.BYPASS_SUMMARY).get("tokens")>0,"charged to its own share");
 }
 @Test void aRequestThatCoversASecretFindingGetsNoSummaryAndNothingIsSent(){
  blocking("ImmutableField","PMD","A.java");blocking("private-key","Betterleaks","watchtower_new_text.txt");
  var summary=bypass.summarize("alice",request("Test fixtures",BypassReasonCode.TEST_CODE));
  assertEquals("BLOCKED",summary.get("state"));assertFalse(summary.containsKey("total"),"not even counts");assertTrue(sent.isEmpty());
  assertEquals(0L,fx.budgets.usedToday(AssistantFeature.BYPASS_SUMMARY).get("tokens"));
  blocking("Whatever","BETTERLEAKS","B.java");
  assertEquals("BLOCKED",bypass.summarize("alice",request("again",BypassReasonCode.OTHER)).get("state"),"modules match ignoring case");
 }
 void plain(String rule,String module,String file){
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->{
   var v=new PullRequestViolationEntity();v.setScan(fx.database.records.find(PullRequestScanEntity.class,1L));v.setViolationName(rule);v.setFileName(file);v.setLineNum(1);
   if(module!=null)v.setRuleIdentity(new RuleExecutionIdentity(null,module,"a".repeat(64),null,null));fx.database.records.insert(v);
  });
 }
 @Test void aScanWhoseFindingsAreNotFlaggedBlockingIsStillCheckedForSecretsBeforeAnythingIsSent(){
  plain("ImmutableField","PMD","A.java");plain("private-key","Betterleaks","watchtower_new_text.txt");
  long id=request("x",BypassReasonCode.OTHER);
  var summary=bypass.summarize("alice",id);
  assertEquals("BLOCKED",summary.get("state"),"a secret in the scan is found even when no finding is flagged blocking");assertFalse(summary.containsKey("total"));assertTrue(sent.isEmpty());
  assertEquals(Map.of("blocked","secret finding"),bypass.facts("alice",id),"and the chat tool returns only the marker");
 }
 @Test void findingsWithNoRecordedRuleCannotBeToldFromASecretEvenWhenNoneIsFlaggedBlocking(){
  plain("old-finding",null,"A.java");
  var summary=bypass.summarize("alice",request("x",BypassReasonCode.OTHER));
  assertEquals("BLOCKED",summary.get("state"));assertTrue(sent.isEmpty());
 }
 @Test void aScanWithOnlyOrdinaryFindingsStillGetsASummaryWhenNoneIsFlaggedBlocking(){
  plain("ImmutableField","PMD","A.java");
  var summary=bypass.summarize("alice",request("x",BypassReasonCode.OTHER));
  assertEquals("OK",summary.get("state"));assertEquals(0L,summary.get("total"),"nothing is flagged blocking, so nothing is counted as blocking");
 }
 @Test void aReasonThatLooksLikeASecretIsWithheldFromTheModel(){
  blocking("ImmutableField","PMD","A.java");
  var summary=bypass.summarize("alice",request("the key is sk-abcdefghijklmnopqrstuvwxyz",BypassReasonCode.OTHER));
  assertEquals("OK",summary.get("state"));assertFalse(sent.getFirst().input().contains("sk-abc"));assertTrue(sent.getFirst().input().contains("withheld"));
 }
 @Test void aNoteThatDecidesOrLooksLikeASecretIsDroppedButTheCountsStay(){
  blocking("ImmutableField","PMD","A.java");long id=request("x",BypassReasonCode.OTHER);
  replies.add(reply("{\"risk_note\":\"You should approve this request.\"}"));
  var decided=bypass.summarize("alice",id);assertNull(decided.get("risk_note"));assertEquals(1L,decided.get("total"));
  replies.add(reply("{\"risk_note\":\"password=hunter2hunter2 is in the reason\"}"));assertNull(bypass.summarize("alice",id).get("risk_note"));
  replies.add(reply("not json"));assertNull(bypass.summarize("alice",id).get("risk_note"));
  replies.add(reply("{\"risk_note\":\""+"x".repeat(300)+"\"}"));assertNull(bypass.summarize("alice",id).get("risk_note"));
 }
 @Test void theSwitchTheKeyAndTheGrantsAreChecked()throws Exception{
  blocking("ImmutableField","PMD","A.java");long id=request("x",BypassReasonCode.OTHER);
  keyConfigured.set(false);assertEquals("NO_API_KEY",bypass.summarize("alice",id).get("state"));keyConfigured.set(true);
  fx.configure(c->AssistantFixture.slice(c,"bypassSummary",false,200_000,200_000));
  assertEquals("OFF",bypass.summarize("alice",id).get("state"));assertTrue(sent.isEmpty());
  doThrow(new AccessDeniedException("no")).when(fx.access).require("mallory","PR Scan Bypass");
  assertThrows(AccessDeniedException.class,()->bypass.summarize("mallory",id),"only someone who can decide a bypass sees a summary");
  assertEquals(404,assertThrows(ResponseStatusException.class,()->{fx.configure(c->AssistantFixture.slice(c,"bypassSummary",true,200_000,200_000));bypass.summarize("alice",9999);}).getStatusCode().value());
 }
 @Test void aFullShareStopsTheSummaryWhileChatKeepsWorking()throws Exception{
  blocking("ImmutableField","PMD","A.java");long id=request("x",BypassReasonCode.OTHER);
  fx.configure(c->AssistantFixture.slice(c,"bypassSummary",true,500,500));
  assertEquals(429,assertThrows(ResponseStatusException.class,()->bypass.summarize("alice",id)).getStatusCode().value());assertTrue(sent.isEmpty());
  assertTrue(fx.budgets.canAfford("alice",fx.cfg(),fx.model(),20_000,2_048),"chat is not held back");
 }
 @Test void textThatLooksLikeASecretIsWithheldWholeBeforeAnyShortening(){
  for(String secret:List.of("-----BEGIN RSA PRIVATE KEY-----\n"+"A".repeat(600),"Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123","token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig","slack xoxb-1234567890-abcdefghij","clone https://deploy:hunter2secret@git.example.com/x.git","aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5hI7jK9m"))
   assertTrue(SecretLooks.looksLikeSecret(secret),secret);
  for(String plain:List.of("Authorization failed for registry","//ClassOrInterfaceDeclaration[ends-with(@SimpleName, 'Controller')]","(?i)foo\\s*=\\s*bar","Plan expansion timed out after 30 seconds"))
   assertFalse(SecretLooks.looksLikeSecret(plain),plain);
  assertEquals("[withheld: it looked like it contained a secret]",JobDiagnosisService.clean("-----BEGIN RSA PRIVATE KEY-----\n"+"A".repeat(600),400),"a key cut in half by shortening would otherwise pass");
  assertEquals(400,JobDiagnosisService.clean("timed out ".repeat(100),400).length());
 }
 @Test void aRequestWithAFindingWhoseRuleIsUnknownIsBlockedLikeASecret(){
  blocking("ImmutableField","PMD","A.java");
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->{
   var v=new PullRequestViolationEntity();v.setScan(fx.database.records.find(PullRequestScanEntity.class,1L));v.setViolationName("legacy-rule");v.setFileName("B.java");v.setLineNum(1);v.setBlocking(true);fx.database.records.insert(v);
  });
  assertEquals("BLOCKED",bypass.summarize("alice",request("x",BypassReasonCode.OTHER)).get("state"));assertTrue(sent.isEmpty());
 }
 @Test void aNoteThatHintsAtAVerdictOrRunsOnIsDropped(){
  blocking("ImmutableField","PMD","A.java");long id=request("x",BypassReasonCode.OTHER);
  for(String bad:List.of("Recommend approval of this request.","This looks safe to bypass.","Looks fine to me, go ahead.","Two High findings. Check the files.","Declined requests need a new scan."))
  {replies.add(reply("{\"risk_note\":\""+bad+"\"}"));assertNull(bypass.summarize("alice",id).get("risk_note"),bad);}
  replies.add(reply("{\"risk_note\":\"Two High findings are covered; check the files before you decide.\"}"));assertNotNull(bypass.summarize("alice",id).get("risk_note"));
 }
 @Test void aLongReasonIsCutAndOnlyJobsFromTheQueuePageAreDiagnosed(){
  blocking("ImmutableField","PMD","A.java");
  bypass.summarize("alice",request("fine ".repeat(190),BypassReasonCode.OTHER));
  assertTrue(sent.getFirst().input().length()<900,"a long reason is cut to 500 characters");
  var job=new AsyncJobEntity();job.setType(AsyncJobType.RULE_CANDIDATE_TEST);job.setStatus(AsyncJobStatus.FAILED);job.setDedupKey("k4");job.setCreatedAt(1);job.setCreatedBy("system");job.setError("boom");
  long id=save(job);
  assertEquals("This kind of job is not diagnosed.",assertThrows(IllegalArgumentException.class,()->diagnosis.diagnose("alice",id)).getMessage());
 }
 @Test void onlyAProviderThatRefusedBeforeProcessingGetsItsChargeBack()throws Exception{
  blocking("ImmutableField","PMD","A.java");long id=request("x",BypassReasonCode.OTHER);
  var failing=new StructuredFeatureCall(fx.settings,R1Database.keys(keyConfigured),fx.budgets,request->{throw new LlmClient.ProviderFailure(failure.get(),false,0);});
  var service=new BypassSummaryService(failing,fx.database.records,secrets,fx.access);
  failure.set("PROVIDER_AUTHENTICATION");assertThrows(ResponseStatusException.class,()->service.summarize("alice",id));
  assertEquals(0L,fx.budgets.usedToday(AssistantFeature.BYPASS_SUMMARY).get("tokens"),"a refused request costs nothing");
  failure.set("PROVIDER_PROTOCOL");assertThrows(ResponseStatusException.class,()->service.summarize("alice",id));
  assertTrue(fx.budgets.usedToday(AssistantFeature.BYPASS_SUMMARY).get("tokens")>0,"a request that may have been processed stays charged");
 }
 final java.util.concurrent.atomic.AtomicReference<String> failure=new java.util.concurrent.atomic.AtomicReference<>("PROVIDER_PROTOCOL");
 @Test void theAiFeaturesFollowTheChatMasterSwitch()throws Exception{
  blocking("ImmutableField","PMD","A.java");long id=request("x",BypassReasonCode.OTHER);
  fx.configure(c->c.put("enabled",false));
  assertEquals("CHAT_OFF",bypass.summarize("alice",id).get("state"));assertTrue(sent.isEmpty());
 }
 @Test void theHelpersAPageShowsAreOnlyThoseThatWillWorkForThatPerson()throws Exception{
  var availability=new HelperAvailability(calls,fx.access,fx.settings);
  var all=availability.of("alice");
  assertEquals(Boolean.FALSE,all.get("draft"),"page context is off");assertTrue(all.get("bypass"));assertTrue(all.get("diagnose"));assertFalse(all.get("triage"),"batch triage is off and needs the source grants");
  fx.configure(c->{AssistantFixture.slice(c,"batchTriage",true,200_000,200_000);((com.fasterxml.jackson.databind.node.ObjectNode)c.get("features").get("enabled")).put("contextCards",true);});
  when(fx.access.authorities("alice")).thenReturn(Set.of("Assistant Use","Scan Results View","PR Scan Bypass","Repository Settings View","Assistant Source Read"));
  var on=availability.of("alice");assertTrue(on.get("draft"));assertTrue(on.get("triage"));
  when(fx.access.authorities("viewer")).thenReturn(Set.of("Assistant Use","Scan Results View"));
  var viewer=availability.of("viewer");assertTrue(viewer.get("diagnose"));assertFalse(viewer.get("bypass"),"deciding a bypass needs PR Scan Bypass");assertFalse(viewer.get("triage"));
  when(fx.access.authorities("nobody")).thenReturn(Set.of("Scan Results View","PR Scan Bypass"));
  assertTrue(availability.of("nobody").values().stream().noneMatch(Boolean::booleanValue),"nothing without Assistant Use");
  fx.configure(c->c.put("enabled",false));
  assertTrue(availability.of("alice").values().stream().noneMatch(Boolean::booleanValue),"chat off: no helper");
 }
 @Test void aFailedIntegrationCheckIsDiagnosedFromACleanedErrorAndPointsAtTheFixPage(){
  var job=new AsyncJobEntity();job.setType(AsyncJobType.INTEGRATION_HEALTH);job.setStatus(AsyncJobStatus.DONE);job.setDedupKey("k1");job.setCreatedAt(1);job.setCreatedBy("system");
  job.setProgress("2 checked, 1 failing: Example (Amazon ECR)");job.setError("Authorization failed with token=abc123def456 for registry");
  long id=save(job);
  replies.add(reply("{\"likely_cause\":\"The Amazon ECR sign-in for Example was refused.\",\"next_step\":\"Replace the ECR credentials in Integrations and test the connection.\"}"));
  var out=diagnosis.diagnose("alice",id);
  assertEquals("OK",out.get("state"));assertEquals("/apisettings",out.get("fix_page"));assertTrue(((String)out.get("next_step")).contains("Integrations"));
  var input=sent.getFirst().input();assertTrue(input.contains("Example"));assertFalse(input.contains("abc123"));assertTrue(input.contains("withheld"));assertTrue(input.contains("Integration check"));
 }
 @Test void aJobThatDidNotFailIsNotDiagnosed(){
  var job=new AsyncJobEntity();job.setType(AsyncJobType.CATALOG_SYNC);job.setStatus(AsyncJobStatus.DONE);job.setDedupKey("k2");job.setCreatedAt(1);job.setCreatedBy("system");job.setProgress("1 repositories, 0 changed, 0 gone");
  long id=save(job);
  assertThrows(IllegalArgumentException.class,()->diagnosis.diagnose("alice",id));assertTrue(sent.isEmpty());
  assertEquals(404,assertThrows(ResponseStatusException.class,()->diagnosis.diagnose("alice",99999)).getStatusCode().value());
 }
 @Test void aDiagnosisThatIsNotTwoCleanSentencesIsDropped(){
  var job=new AsyncJobEntity();job.setType(AsyncJobType.EXPAND_PLAN);job.setStatus(AsyncJobStatus.FAILED);job.setDedupKey("k3");job.setCreatedAt(1);job.setCreatedBy("system");job.setError("Plan expansion timed out");
  long id=save(job);
  replies.add(reply("{\"likely_cause\":\"\",\"next_step\":\"Retry.\"}"));
  assertEquals("NO_ANSWER",diagnosis.diagnose("alice",id).get("state"));
  replies.add(reply("{\"likely_cause\":\"Catalog was slow.\",\"next_step\":\"Retry the run.\"}"));
  var ok=diagnosis.diagnose("alice",id);assertEquals("OK",ok.get("state"));assertFalse(ok.containsKey("fix_page"),"no single page fixes a timeout");
 }
}
