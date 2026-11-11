package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.env.Environment;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionTemplate;
import com.tracelink.appsec.watchtower.core.alerting.*;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity;
import com.tracelink.appsec.watchtower.core.alerting.repository.*;
import com.tracelink.appsec.watchtower.core.assistant.alerts.AlertRouteChangeSetService;
import com.tracelink.appsec.watchtower.core.assistant.digest.HomeDigestService;
import com.tracelink.appsec.watchtower.core.assistant.features.*;
import com.tracelink.appsec.watchtower.core.assistant.tools.OperationsTools;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.job.*;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.*;

/** The tools for Home, jobs, alerts, bypass requests and missed cases: reads return what the page shows, one drafts, none applies. */
class AssistantOperationsToolsTest {
 static final Set<String> GRANTS=Set.of("Assistant Use","Scan Results View","Scan Dashboard View","PR Scan Bypass","Alert Settings View","Alert Settings Modify","Assistant Source Read","Repository Settings View");
 @TempDir Path dir;AssistantFixture fx;AlertSettingsService alerts;AlertRouteChangeSetService changes;HomeDigestService home;FixtureDraftService fixtures;AssistantSecretFindings secrets;
 List<AssistantTool> tools;long platform,appsec,secretRoute;

 @SuppressWarnings("unchecked") static <T> ObjectProvider<T> provider(T value){ObjectProvider<T> p=mock(ObjectProvider.class);when(p.getObject()).thenReturn(value);return p;}
 @BeforeEach void setup()throws Exception{
  fx=new AssistantFixture(dir,GRANTS);fx.tools.setSettings(fx.settings);
  switches(true,true);
  fx.database.jdbc.update("INSERT INTO application_persistence_locks(lock_name) VALUES (?)","alert-route-configuration");
  for(var name:fx.database.jdbc.queryForList("SELECT constraint_name FROM information_schema.table_constraints WHERE table_name='alert_routes' AND constraint_type='CHECK'",String.class))fx.database.jdbc.execute("ALTER TABLE alert_routes DROP CONSTRAINT \""+name+"\"");
  var calls=new StructuredFeatureCall(fx.settings,R1Database.keys(fx.keyConfigured),fx.budgets,request->null);
  var registry=new AlertTypeRegistry();registry.register("SECRET_DETECTED","A secret was found in a pull request",true);registry.register("SECRET_LIVE","A secret was confirmed working",false);
  alerts=new AlertSettingsService(fx.database.repository(AlertChannelRepository.class),fx.database.repository(AlertRouteRepository.class),fx.database.repository(AlertLogRepository.class),registry,mock(GoogleChatSender.class),EncryptionType.NONE,mock(Environment.class));
  changes=fx.database.service(new AlertRouteChangeSetService(fx.database.records,alerts,fx.access,fx.settings));
  home=mock(HomeDigestService.class);fixtures=mock(FixtureDraftService.class);secrets=mock(AssistantSecretFindings.class);
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(),Set.of("private-key"),Set.of("betterleaks")));
  var jobs=new JobDiagnosisService(calls,fx.database.repository(AsyncJobRepository.class),fx.access);
  var bypass=new BypassSummaryService(calls,fx.database.records,secrets,fx.access);
  tools=new OperationsTools(provider(home),provider(jobs),provider(bypass),provider(fixtures),provider(changes),provider(fx.database.records)).tools();
  tools.forEach(fx.tools::register);
  platform=channel("platform");appsec=channel("appsec");secretRoute=route("SECRET_DETECTED",platform,RulePriority.MEDIUM);
  fx.database.seedPr(1,1);
 }
 static final List<String> FEATURES=List.of("alertCopilot","missedCase","homeDigest","jobDiagnosis","bypassSummary");
 /** Every feature the tools sit behind, all on or all off, with the chat page cards on or off. */
 void switches(boolean features,boolean cards)throws Exception{
  fx.configure(c->{for(String feature:FEATURES)AssistantFixture.slice(c,feature,features,200_000,200_000);((ObjectNode)c.get("features").get("enabled")).put("contextCards",cards);});
 }
 @AfterEach void close(){fx.close();}

 long channel(String name){
  return new TransactionTemplate(fx.database.tx).execute(s->{var c=new AlertChannelEntity();c.setName(name);c.setWebhookUrl("https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=faketoken");fx.database.records.insert(c);return c.getId();});
 }
 long route(String type,long channel,RulePriority min){
  return new TransactionTemplate(fx.database.tx).execute(s->{var r=new AlertRouteEntity();r.setAlertType(type);r.setChannel(fx.database.records.find(AlertChannelEntity.class,channel));r.setMinPriority(min);
   r.setAggregation(AlertAggregation.PER_SCAN);r.setDedupeWindowHours(720);r.setUpdatedAt(1);fx.database.records.insert(r);return r.getId();});
 }
 int routes(){return alerts.getRoutes().size();}
 int drafts(){return fx.database.records.maps("SELECT c.id AS id FROM AlertRouteChangeSetEntity c",0,100).size();}
 JsonNode call(String name,String args){return fx.tools.invoke("alice",name,args,65536,AssistantState.TOOL_VERSION,"turn-1").path("data");}
 static String json(Object value){try{return AssistantState.mapper().writeValueAsString(value);}catch(Exception e){throw new IllegalStateException(e);}}
 static Map<String,Object> operation(String type,Long routeId,String alertType,Long channel,String min,Long baseVersion){
  var m=new LinkedHashMap<String,Object>();m.put("type",type);m.put("routeId",routeId);m.put("alertType",alertType);m.put("channelId",channel);m.put("minPriority",min);m.put("apiLabelFilter",null);
  m.put("repoInclude",null);m.put("repoExclude",null);m.put("aggregation","PER_SCAN");m.put("dedupeWindowHours",720);m.put("baseVersion",baseVersion);return m;
 }
 @SafeVarargs static String draftArgs(Map<String,Object>... operations){return json(Map.of("operations_json",json(List.of(operations))));}

 @Test void theToolsDeclareTheirEffectAndOnlyTheAlertDraftWritesAnything(){
  assertEquals(Set.of("get_home_overview","get_job","get_alert_config","get_bypass_request","get_missed_case_evidence","prepare_alert_route_changes"),new TreeSet<>(tools.stream().map(AssistantTool::name).toList()));
  for(var t:tools)assertEquals("prepare_alert_route_changes".equals(t.name())?AssistantTool.Effect.DRAFT_PREPARATION:AssistantTool.Effect.EVIDENCE_READ,t.effect(),t.name());
  assertEquals(AssistantFeature.ALERT_COPILOT,fx.tools.all().stream().filter(t->t.name().equals("prepare_alert_route_changes")).findFirst().orElseThrow().feature());
  assertEquals(AssistantFeature.MISSED_CASE,fx.tools.all().stream().filter(t->t.name().equals("get_missed_case_evidence")).findFirst().orElseThrow().feature());
  assertTrue(fx.tools.schemas("alice").toString().contains("prepare_alert_route_changes"));
  assertTrue(fx.tools.schemas("alice").toString().contains("get_alert_config"));
 }
 @Test void eachToolStopsWhenItsSwitchIsOffAndNeedsTheGrantsOfItsPage()throws Exception{
  switches(false,false);
  var offered=fx.tools.schemas("alice").toString();
  for(String name:List.of("get_home_overview","get_job","get_alert_config","get_bypass_request","get_missed_case_evidence","prepare_alert_route_changes"))assertFalse(offered.contains("\""+name+"\""),name);
  assertThrows(IllegalArgumentException.class,()->call("get_alert_config","{}"));
  assertThrows(IllegalArgumentException.class,()->call("prepare_alert_route_changes",draftArgs(operation("ADD",null,"SECRET_LIVE",appsec,null,null))));
  assertEquals(0,drafts());
  switches(true,true);
  when(fx.access.authorities("viewer")).thenReturn(Set.of("Assistant Use","Scan Results View"));
  var viewer=fx.tools.schemas("viewer").toString();
  assertTrue(viewer.contains("get_job"));assertFalse(viewer.contains("get_alert_config"),"alert settings need Alert Settings View");assertFalse(viewer.contains("get_home_overview"));assertFalse(viewer.contains("prepare_alert_route_changes"));
  doThrow(new AccessDeniedException("no")).when(fx.access).require("viewer","Alert Settings View");
  assertThrows(AccessDeniedException.class,()->fx.tools.invoke("viewer","get_alert_config","{}",16384,AssistantState.TOOL_VERSION,"turn-1"));
 }
 @Test void aToolStopsWithItsOwnFeatureSwitchEvenWhenPageCardsAreOn()throws Exception{
  switches(true,true);
  fx.configure(c->AssistantFixture.slice(c,"homeDigest",false,200_000,200_000));
  var offered=fx.tools.schemas("alice").toString();
  assertFalse(offered.contains("get_home_overview"),"Home counts need the Home digest switch");
  assertTrue(offered.contains("get_alert_config"),"the other tools keep working");
  assertThrows(IllegalArgumentException.class,()->call("get_home_overview","{}"));
 }
 @Test void aToolIsNotOfferedToACheckpointFromBeforeItExisted()throws Exception{
  switches(true,true);
  assertFalse(fx.tools.schemas("alice","r5-v1").toString().contains("get_alert_config"));
  assertTrue(fx.tools.schemas("alice",AssistantState.TOOL_VERSION).toString().contains("get_alert_config"));
 }
 @Test void homeComesBackAsCountsOnly(){
  when(home.currentCounts()).thenReturn(Map.of("this_week",Map.of("scans_finished",4532,"findings",4040),"now",Map.of("integrations_failing",4)));
  var data=call("get_home_overview","{}");
  assertEquals(4532,data.path("this_week").path("scans_finished").asInt());assertEquals(4,data.path("now").path("integrations_failing").asInt());
 }
 @Test void theAlertConfigShowsChannelNamesAndRouteVersionsButNeverAWebhookAddress(){
  var data=call("get_alert_config","{}");var text=data.toString();
  assertFalse(text.contains("faketoken")||text.contains("googleapis"),"no webhook address");
  assertEquals(2,data.path("channels").size());assertEquals("platform",data.path("channels").get(0).path("name").asText());
  var route=data.path("routes").get(0);assertEquals(secretRoute,route.path("id").asLong());assertTrue(route.has("version"));assertEquals("MEDIUM",route.path("minPriority").asText());assertEquals("SECRET_DETECTED",route.path("alertType").asText());
  channel("sk-abcdefghijklmnopqrstuvwxyz");
  assertFalse(call("get_alert_config","{}").toString().contains("sk-abcdef"),"a channel name that looks like a secret is withheld");
 }
 @Test void aJobComesBackCleanedAndOnlyForTheJobsOnTheQueuePage(){
  long failing=job(AsyncJobType.INTEGRATION_HEALTH,AsyncJobStatus.FAILED,"1 of 2 failing","Authorization failed with token=abc123def456abc123def456abc123def456 for registry");
  var data=call("get_job","{\"job_id\":"+failing+"}");
  assertEquals("FAILED",data.path("status").asText());assertTrue(data.path("error").asText().contains("withheld"));assertFalse(data.toString().contains("abc123"));
  long hidden=job(AsyncJobType.RULE_CANDIDATE_TEST,AsyncJobStatus.FAILED,"","boom");
  assertThrows(IllegalArgumentException.class,()->call("get_job","{\"job_id\":"+hidden+"}"),"other kinds of job are not available");
  assertThrows(IllegalArgumentException.class,()->call("get_job","{\"job_id\":987654}"));
 }
 long job(AsyncJobType type,AsyncJobStatus status,String progress,String error){
  return new TransactionTemplate(fx.database.tx).execute(s->{var job=new AsyncJobEntity();job.setType(type);job.setStatus(status);job.setDedupKey("k"+System.nanoTime());job.setCreatedAt(System.currentTimeMillis()-120000);job.setCreatedBy("system");job.setProgress(progress);job.setError(error);
   return fx.database.records.insert(job).getId();});
 }
 long bypassRequest(String reason){
  var r=new PullRequestBypassRequestEntity();r.setApiLabel("Bitbucket");r.setRepoName("wt-test");r.setPrId("58");r.setScanId(1);r.setRequestedBy("casey");r.setReason(reason);r.setCreatedAt(1);r.setReasonCode(BypassReasonCode.TEST_CODE);
  return fx.database.records.insert(r).getId();
 }
 void blocking(String rule,String module){
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->{
   var v=new PullRequestViolationEntity();v.setScan(fx.database.records.find(PullRequestScanEntity.class,1L));v.setViolationName(rule);v.setFileName("A.java");v.setLineNum(1);v.setBlocking(true);
   v.setRuleIdentity(new RuleExecutionIdentity(null,module,"a".repeat(64),null,null));fx.database.records.insert(v);
  });
 }
 @Test void aBypassRequestIsFactsUntilItCoversASecretAndTheReasonIsWithheldWhenItLooksLikeOne(){
  blocking("ImmutableField","PMD");blocking("ImmutableField","PMD");
  long id=bypassRequest("Test fixtures with fake keys; tracked in SEC-123");
  var data=call("get_bypass_request","{\"request_id\":"+id+"}");
  assertFalse(data.has("requested_by"),"no name of the person who asked");assertEquals("TEST_CODE",data.path("reason_code").asText());assertEquals(2,data.path("blocking_findings").asInt());assertTrue(data.path("requester_reason").asText().contains("SEC-123"));
  long odd=bypassRequest("the key is sk-abcdefghijklmnopqrstuvwxyz");
  assertTrue(call("get_bypass_request","{\"request_id\":"+odd+"}").path("requester_reason").asText().contains("withheld"));
  blocking("private-key","Betterleaks");
  var blocked=call("get_bypass_request","{\"request_id\":"+id+"}");
  assertEquals("secret finding",blocked.path("blocked").asText());assertFalse(blocked.has("requested_by"),"nothing else about a request that covers a secret");assertFalse(blocked.has("requester_reason"));
  when(fx.access.authorities("viewer")).thenReturn(Set.of("Assistant Use","Scan Results View"));
  assertFalse(fx.tools.schemas("viewer").toString().contains("get_bypass_request"),"deciding a bypass needs PR Scan Bypass");
 }
 @Test void aMissedCaseGivesTheMaskedLinesOrOnlyTheMarker(){
  var facts=Map.<String,Object>of("weakness","CWE-79","vulnerable_lines",List.of(Map.of("line",88,"text","out.write(name);")));
  when(fixtures.evidence(anyString(),eq("11111111-1111-1111-1111-111111111111"))).thenReturn(Map.of("state","READY","facts",facts));
  var data=call("get_missed_case_evidence","{\"case_id\":\"11111111-1111-1111-1111-111111111111\"}");
  assertEquals("CWE-79",data.path("evidence").path("weakness").asText());assertTrue(data.path("note").asText().contains("stay in this chat"));
  when(fixtures.evidence(anyString(),eq("22222222-2222-2222-2222-222222222222"))).thenReturn(Map.of("state","BLOCKED","message","A secret was recorded near this line"));
  var blocked=call("get_missed_case_evidence","{\"case_id\":\"22222222-2222-2222-2222-222222222222\"}");
  assertEquals("secret finding",blocked.path("blocked").asText());assertFalse(blocked.toString().contains("recorded near"),"no detail for a secret");
  when(fixtures.evidence(anyString(),eq("33333333-3333-3333-3333-333333333333"))).thenReturn(Map.of("state","NOT_READY","message","No fixed commit was recorded."));
  assertThrows(IllegalArgumentException.class,()->call("get_missed_case_evidence","{\"case_id\":\"33333333-3333-3333-3333-333333333333\"}"));
 }
 @Test void theAlertDraftToolPreparesOneDraftForAPersonAndChangesNoRoute(){
  var args=draftArgs(operation("ADD",null,"SECRET_LIVE",appsec,null,null));
  var data=call("prepare_alert_route_changes",args);
  assertTrue(data.path("reviewUrl").asText().matches("/assistant/alert-changes/[0-9a-f-]{36}/review"));assertEquals("DRAFT",data.path("status").asText());assertEquals(1,data.path("changes").asInt());
  assertTrue(data.path("message").asText().contains("No routes were changed"));
  assertEquals(1,routes(),"a draft changes no route");assertEquals(1,drafts());
  assertEquals(data.path("changeSetId").asText(),call("prepare_alert_route_changes",args).path("changeSetId").asText(),"the same call in the same turn is the same draft");assertEquals(1,drafts());
  assertEquals("DRAFT",changes.get(data.path("changeSetId").asText(),"alice").status());
 }
 @Test void aChangeNeedsTheRoutesVersionAndAStaleOrBadDraftIsRefused(){
  long version=alerts.getRoutes().get(0).getConfigurationVersion();
  assertThrows(IllegalArgumentException.class,()->call("prepare_alert_route_changes",draftArgs(operation("UPDATE",secretRoute,"SECRET_DETECTED",platform,"HIGH",null))),"UPDATE without baseVersion");
  assertThrows(IllegalArgumentException.class,()->call("prepare_alert_route_changes",draftArgs(operation("REMOVE",secretRoute,null,null,null,null))),"REMOVE without baseVersion");
  assertThrows(IllegalArgumentException.class,()->call("prepare_alert_route_changes",draftArgs(operation("UPDATE",secretRoute,"SECRET_DETECTED",platform,"HIGH",version+5))),"a version the route never had");
  assertThrows(IllegalArgumentException.class,()->call("prepare_alert_route_changes",draftArgs(operation("ADD",null,"SECRET_LIVE",9999L,null,null))),"a channel that does not exist");
  assertThrows(IllegalArgumentException.class,()->call("prepare_alert_route_changes",json(Map.of("operations_json","not json"))));
  assertEquals(0,drafts());
  var ok=call("prepare_alert_route_changes",draftArgs(operation("UPDATE",secretRoute,"SECRET_DETECTED",platform,"HIGH",version)));
  assertEquals(1,ok.path("changes").asInt());assertEquals(RulePriority.MEDIUM,alerts.getRoutes().get(0).getMinPriority(),"still not applied");
  var many=new ArrayList<Map<String,Object>>();for(int i=0;i<6;i++)many.add(operation("ADD",null,"SECRET_LIVE",appsec,null,null));
  assertThrows(IllegalArgumentException.class,()->call("prepare_alert_route_changes",json(Map.of("operations_json",json(many)))),"at most five changes");
 }
 @Test void aModelCannotCallAToolThatWouldApplyAnAlertChangeOrAChannelChange(){
  for(String name:List.of("apply_alert_route_changes","approve_alert_route_changes","add_alert_channel","delete_alert_route"))
   assertThrows(IllegalArgumentException.class,()->fx.tools.invoke("alice",name,"{}",16384,AssistantState.TOOL_VERSION,"turn-1"),name);
  assertEquals(1,routes());assertEquals(2,alerts.getChannels().size());
 }
}
