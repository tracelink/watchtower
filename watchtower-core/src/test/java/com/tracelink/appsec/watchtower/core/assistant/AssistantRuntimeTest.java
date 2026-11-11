package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import java.nio.file.*;
import java.io.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;
import com.fasterxml.jackson.databind.node.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;

class AssistantRuntimeTest {
 final java.util.concurrent.atomic.AtomicBoolean keyConfigured=new java.util.concurrent.atomic.AtomicBoolean(true);
 @TempDir Path dir;R1Database database;AssistantSettingsService settings;AssistantPersistence db;
 AssistantAccess access;AssistantToolRegistry tools;AssistantBudgetService budgets;final List<Object> accepted=new CopyOnWriteArrayList<>();
 @BeforeEach void setup()throws Exception{
  database=new R1Database();settings=database.service(new AssistantSettingsService(database.records,R1Database.keys(keyConfigured),null,false));keyConfigured.set(true);
  var config=AssistantState.mapper().valueToTree(settings.get().settings());((ObjectNode)config).put("enabled",true).put("defaultModel","fixture-model").put("defaultEffort","low");
  ((ObjectNode)config).putArray("allowedModels").addObject().put("id","fixture-model").put("inputTokenLimit",65536).put("outputTokenLimit",8192).put("inputMicrosPerMillion",1000000).put("outputMicrosPerMillion",2000000).put("validatedAt","2026-10-10").put("validationRef","fixture:responses-v1").putArray("efforts").add("low").add("none");
  settings.save(new AssistantSettingsService.Versioned(1,settings.decode(config.toString())),"admin");
  access=mock(AssistantAccess.class);when(access.authorities(anyString())).thenReturn(Set.of("Assistant Use","Ruleset View","Scan Results View"));
  var rules=mock(RuleService.class);when(rules.getRules()).thenReturn(List.of());var rulesets=mock(RulesetService.class);when(rulesets.getRulesets()).thenReturn(List.of());
  tools=database.service(new AssistantToolRegistry(access,rules,rulesets,new RuleHealthService(database.records,6,3,.5),mock(RuleReviewService.class),database.records,mock(AssistantSourceTools.class),mock(AssistantSecretFindings.class)));
  db=database.service(new AssistantPersistence(database.records,database.tx,new LocalAssistantTranscriptStore(dir),settings,access,accepted::add));budgets=database.service(new AssistantBudgetService(database.records,database.tx));
 }
 @AfterEach void close(){database.close();}
 AssistantPersistence.Turn submit()throws Exception{return db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"Explain an existing rule",null,null),"engineer");}
 AssistantPersistence.Turn claim(AssistantPersistence.Turn t){return db.claim(t.id(),UUID.randomUUID().toString()).orElseThrow();}
 AssistantPersistence.Turn submitAs(String owner)throws Exception{return db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"Explain an existing rule",null,null),owner);}
 static void await(java.util.function.BooleanSupplier done,long millis)throws InterruptedException{long end=System.nanoTime()+millis*1000000;while(!done.getAsBoolean()){if(System.nanoTime()>end)fail("Timed out waiting for assistant work");Thread.sleep(10);}}
 AssistantTurnRunner completing(Map<String,Integer> runs,long millis){var runner=mock(AssistantTurnRunner.class);doAnswer(inv->{AssistantPersistence.Turn t=inv.getArgument(0);runs.merge(t.id(),1,Integer::sum);Thread.sleep(millis);db.terminal(t,"COMPLETED",null);return null;}).when(runner).run(any());return runner;}
 record Sent(String event,Object data) { }
 static class Collect implements AssistantStreams.Sink {final List<Sent> sent=new ArrayList<>();boolean done;
  @Override public void send(String event,Object data){sent.add(new Sent(event,data));}@Override public void keepAlive(){}@Override public void complete(){done=true;}
  Map<?,?> last(){return (Map<?,?>)sent.getLast().data();}}
 @Test void wakeIsPublishedOnlyAfterCommitAndRolledBackInputNeverDispatches()throws Exception{
  new org.springframework.transaction.support.TransactionTemplate(database.tx).executeWithoutResult(s->{try{submit();}catch(Exception e){throw new IllegalStateException(e);}s.setRollbackOnly();});
  assertTrue(accepted.isEmpty());assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_turns",Integer.class));
  var t=submit();assertEquals(List.of(new AssistantPersistence.Accepted(t.id())),accepted);
 }
 @Test void competingPodsDrainEveryAcceptedTurnExactlyOnceWithoutPeriodicPolling()throws Exception{
  Map<String,Integer> runs=new ConcurrentHashMap<>();var podA=new AssistantWorker(db,settings,completing(runs,100),2);var podB=new AssistantWorker(db,settings,completing(runs,100),2);
  try{List<String> ids=new ArrayList<>();long start=System.nanoTime();
   // Six turns exceed the four shared slots: freed workers must drain the rest without a recovery poll.
   for(int i=0;i<6;i++){ids.add(submitAs("engineer"+i).id());podA.wake();podB.wake();}
   await(()->ids.stream().allMatch(id->"COMPLETED".equals(db.turn(id).status())),5000);long elapsed=(System.nanoTime()-start)/1000000;
   ids.forEach(id->assertEquals(1,runs.get(id),"each turn runs once across pods"));assertTrue(elapsed<3000,"six 100 ms turns on four slots took "+elapsed+" ms");
  }finally{podA.close();podB.close();}
 }
 @Test void periodicRecoveryRunsMissedWakeupsAndExpiredLeasesOnlyWhileEnabled()throws Exception{
  Map<String,Integer> runs=new ConcurrentHashMap<>();var pod=new AssistantWorker(db,settings,completing(runs,0),1);
  try{var missed=submitAs("engineer");var crashed=claim(submitAs("other"));database.jdbc.update("UPDATE assistant_turns SET heartbeat_at=0 WHERE turn_id=?",crashed.id());
   keyConfigured.set(false);pod.recover();Thread.sleep(200);assertTrue(runs.isEmpty());assertEquals("QUEUED",db.turn(missed.id()).status());
   keyConfigured.set(true);pod.recover();
   await(()->"COMPLETED".equals(db.turn(missed.id()).status())&&"COMPLETED".equals(db.turn(crashed.id()).status()),5000);
   assertEquals(2,db.turn(crashed.id()).attempts());assertEquals(1,runs.get(crashed.id()));
  }finally{pod.close();}
 }
 @Test void streamsDeliverChangedDurableProgressWithinBoundsAndRecheckAccess()throws Exception{
  var streams=new AssistantStreams(db,access,tools,1,3600000,0,600000);
  try{var t=submit();var sink=new Collect();var stream=streams.start(t.id(),"engineer",sink);assertEquals("QUEUED",sink.last().get("status"));
   assertEquals(429,assertThrows(ResponseStatusException.class,()->streams.start(t.id(),"engineer",new Collect())).getStatusCode().value());
   streams.tick(stream);assertEquals(1,sink.sent.size());
   var running=claim(t);var progress=db.state(running);progress.activity.addObject().put("tool","get_rule").put("status","read");db.checkpoint(running,progress,false);
   streams.tick(stream);assertEquals("RUNNING",sink.last().get("status"));assertNull(sink.last().get("answer"));assertFalse(sink.done);
   progress.activity.addObject().put("tool","get_rule").put("status","read").put("rule",987654L);
   progress.finish("Done");db.checkpoint(running,progress,true);streams.tick(stream);
   assertEquals("COMPLETED",sink.last().get("status"));assertEquals("Done",sink.last().get("answer"));assertTrue(sink.done);
   // Only rules that exist are cited; a turn that prepared nothing lists no change sets.
   assertEquals(List.of(),sink.last().get("citations"));assertEquals(List.of(),sink.last().get("changeSets"));
   var other=submitAs("other");assertEquals(404,assertThrows(ResponseStatusException.class,()->streams.start(other.id(),"engineer",new Collect())).getStatusCode().value());
   var revoked=new Collect();var second=streams.start(other.id(),"other",revoked);
   doThrow(new org.springframework.security.access.AccessDeniedException("revoked")).when(access).require("other","Assistant Use");streams.tick(second);
   assertEquals("end",revoked.sent.getLast().event());assertTrue(revoked.done);streams.start(t.id(),"engineer",new Collect());
  }finally{streams.close();}
 }
 @Test void streamsEndOnCancellationExpiryAndKillSwitch()throws Exception{
  var streams=new AssistantStreams(db,access,tools,4,3600000,0,600000);
  try{var canceled=submitAs("engineer");var sink=new Collect();var stream=streams.start(canceled.id(),"engineer",sink);db.cancel(canceled.id(),"engineer");streams.tick(stream);assertEquals("CANCELED",sink.last().get("status"));assertTrue(sink.done);
   var expiring=submitAs("other");var expired=new Collect();var second=streams.start(expiring.id(),"other",expired);database.jdbc.update("UPDATE assistant_sessions SET expires_at=0 WHERE session_id=?",expiring.session());streams.tick(second);assertEquals("end",expired.sent.getLast().event());assertTrue(expired.done);
   var busy=submitAs("fourth");for(int i=0;i<3;i++)streams.start(busy.id(),"fourth",new Collect());
   assertEquals(429,assertThrows(ResponseStatusException.class,()->streams.start(busy.id(),"fourth",new Collect())).getStatusCode().value());
   var live=submitAs("third");var off=new Collect();var third=streams.start(live.id(),"third",off);keyConfigured.set(false);streams.tick(third);assertEquals("end",off.sent.getLast().event());assertTrue(off.done);
  }finally{streams.close();}
 }
 LlmClient.Response answer(String text){ArrayNode output=AssistantState.mapper().createArrayNode();output.addObject().put("type","message").put("role","assistant").putArray("content").addObject().put("type","output_text").put("text",text);return new LlmClient.Response(output,"completed",100,50,true);}
 @Test void acceptedInputIsDurableAndIdempotentBeforeDispatch()throws Exception{
  var req=new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"Help me understand",null,null);var t=db.submit(req,"engineer");assertEquals(t.id(),db.submit(req,"engineer").id());assertEquals("Help me understand",db.state(t).messages.get(0).path("text").asText());assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_outbox",Integer.class));assertEquals("QUEUED",db.turn(t.id()).status());
  assertThrows(ResponseStatusException.class,()->db.submit(new AssistantPersistence.Submit(null,req.idempotencyKey(),"different",null,null),"engineer"));
  assertThrows(ResponseStatusException.class,()->db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"second",null,null),"engineer"));
 }
 @Test void simultaneousSubmitsHaveOneSharedSlot()throws Exception {
  ExecutorService workers=Executors.newFixedThreadPool(2);try{var start=new CountDownLatch(1);List<Future<Boolean>> results=new ArrayList<>();for(int i=0;i<2;i++)results.add(workers.submit(()->{start.await();try{submit();return true;}catch(ResponseStatusException e){return false;}}));start.countDown();int accepted=0;for(var f:results)if(f.get())accepted++;assertEquals(1,accepted);}finally{workers.shutdownNow();}
 }
 @Test void scriptedToolLoopPreservesProtocolMasksSecretsAndSettlesBudgets()throws Exception{
  var t=claim(submit());var output=AssistantState.mapper().createArrayNode();output.addObject().put("type","reasoning").put("encrypted_content","opaque-state").putArray("summary");output.addObject().put("type","function_call").put("name","get_engine_playbook").put("call_id","call_1").put("arguments","{\"engine\":\"regex\"}");
  var calls=new java.util.concurrent.atomic.AtomicInteger();LlmClient fake=req->{if(calls.getAndIncrement()==0)return new LlmClient.Response(output,"completed",100,10,true);assertTrue(req.input().toString().contains("opaque-state"));assertTrue(req.input().toString().contains("function_call_output"));return answer("Rule evidence. token=super-secret-value");};
  new AssistantTurnRunner(db,settings,tools,fake,budgets).run(t);assertEquals("COMPLETED",db.turn(t.id()).status());var state=db.state(db.turn(t.id()));assertEquals(2,calls.get());assertTrue(state.answer.contains("[REDACTED]"));assertFalse(state.answer.contains("super-secret"));assertEquals(260,db.turn(t.id()).tokens());assertEquals(1,state.evidence.size());assertTrue(state.activity.toString().contains("get_engine_playbook"));assertEquals(2,database.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_request_reservations WHERE actual_tokens IS NOT NULL",Integer.class));
 }
 @Test void collectedEvidenceCanProduceFinalAnswerWithoutToolCatalogWhileKeepingInputCaps()throws Exception{
  var config=(ObjectNode)AssistantState.mapper().valueToTree(settings.get().settings());((ObjectNode)config.path("allowedModels").get(0)).put("inputTokenLimit",24000);settings.save(new AssistantSettingsService.Versioned(settings.get().version(),settings.decode(config.toString())),"admin");
  var t=claim(submit());var state=db.state(t);state.toolCalls=1;state.iterations=1;
  state.protocol.addObject().put("type","function_call").put("name","get_engine_playbook").put("call_id","saved_evidence").put("arguments","{\"engine\":\"regex\"}");
  state.protocol.addObject().put("type","function_call_output").put("call_id","saved_evidence").put("output","Authorized evidence about the regex engine.");
  var pad=state.protocol.addObject().put("role","user").put("content","");
  var cfg=settings.get().settings();var noTools=new LlmClient.Request(t.model(),t.effort(),state.protocol,AssistantState.mapper().createArrayNode(),cfg.maxOutputTokens(),cfg.providerTimeoutSeconds(),AssistantPersistence.ownerKey(t.owner()),state.promptVersion);
  int base=AssistantState.mapper().writeValueAsBytes(OpenAiLlmClient.payload(noTools)).length;pad.put("content","x".repeat(23000-base));
  var catalog=new LlmClient.Request(t.model(),t.effort(),state.protocol,tools.schemas(t.owner(),state.toolVersion),cfg.maxOutputTokens(),cfg.providerTimeoutSeconds(),AssistantPersistence.ownerKey(t.owner()),state.promptVersion);
  assertTrue(AssistantState.mapper().writeValueAsBytes(OpenAiLlmClient.payload(catalog)).length>24000);db.checkpoint(t,state,false);
  var calls=new java.util.concurrent.atomic.AtomicInteger();LlmClient fake=req->{calls.incrementAndGet();assertTrue(req.tools().isEmpty(),"Further tools must not be offered");assertTrue(req.input().toString().contains("Authorized evidence"),"Collected evidence must remain in the final request");assertTrue(AssistantState.mapper().writeValueAsBytes(OpenAiLlmClient.payload(req)).length<=24000,"Final request must fit the existing allowance");return answer("Answer using collected evidence.");};
  new AssistantTurnRunner(db,settings,tools,fake,budgets).run(db.turn(t.id()));assertEquals(1,calls.get());assertEquals("Answer using collected evidence.",db.state(db.turn(t.id())).answer);assertEquals(24000,settings.get().settings().allowedModels().getFirst().inputTokenLimit());
 }
 @Test void collectedEvidenceStillCannotExceedTheInputAllowance()throws Exception{
  var config=(ObjectNode)AssistantState.mapper().valueToTree(settings.get().settings());((ObjectNode)config.path("allowedModels").get(0)).put("inputTokenLimit",24000);settings.save(new AssistantSettingsService.Versioned(settings.get().version(),settings.decode(config.toString())),"admin");
  var t=claim(submit());var state=db.state(t);state.toolCalls=1;state.protocol.addObject().put("role","user").put("content","x".repeat(24000));db.checkpoint(t,state,false);
  LlmClient fake=req->{fail("An oversized request must never reach the provider, even after evidence was collected");return null;};
  new AssistantTurnRunner(db,settings,tools,fake,budgets).run(db.turn(t.id()));assertEquals("COMPLETED",db.turn(t.id()).status());assertTrue(db.state(db.turn(t.id())).answer.contains("Conversation input limit reached"));
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_request_reservations",Integer.class));
 }
 @Test void recoveryContinuesSavedToolCallWithoutRepeatingModelResponse()throws Exception {
  var first=claim(submit());var state=db.state(first);state.protocol.addObject().put("type","function_call").put("name","search_rules").put("call_id","saved_call").put("arguments","{\"query\":\"test\",\"offset\":0}");state.iterations=1;db.checkpoint(first,state,false);
  database.jdbc.update("UPDATE assistant_turns SET heartbeat_at=0 WHERE turn_id=?",first.id());var second=claim(first);assertTrue(second.leaseVersion()>first.leaseVersion());
  assertThrows(IllegalStateException.class,()->db.checkpoint(first,state,true));
  LlmClient fake=r->{assertTrue(r.input().toString().contains("saved_call"));assertTrue(r.input().toString().contains("function_call_output"));return answer("Recovered evidence");};new AssistantTurnRunner(db,settings,tools,fake,budgets).run(second);assertEquals("COMPLETED",db.turn(first.id()).status());assertEquals("Recovered evidence",db.state(db.turn(first.id())).answer);
 }
 @Test void savedFinalResponseIsPublishedAfterRestartWithoutProviderCall()throws Exception{
  var t=claim(submit());var s=db.state(t);s.pendingAnswer="Already generated";db.checkpoint(t,s,false);database.jdbc.update("UPDATE assistant_turns SET heartbeat_at=0 WHERE turn_id=?",t.id());var next=claim(t);LlmClient fake=r->{fail("Should publish saved response");return null;};new AssistantTurnRunner(db,settings,tools,fake,budgets).run(next);assertEquals("Already generated",db.state(db.turn(t.id())).answer);
 }
 @Test void canceledWorkerCannotPublishOrReserveAgain()throws Exception{
  var t=claim(submit());db.cancel(t.id(),"engineer");assertFalse(db.heartbeat(t));assertThrows(IllegalStateException.class,()->db.checkpoint(t,db.state(t),true));var cfg=settings.get().settings();assertThrows(IllegalStateException.class,()->budgets.reserve(t,cfg,cfg.model(t.model(),t.effort()),100,100));assertEquals("CANCELED",db.turn(t.id()).status());
 }
 @Test void turnBudgetRetainsUncertainSpendAndSettlementIsIdempotent()throws Exception{
  var t=claim(submit());var cfg=settings.get().settings();var model=cfg.model(t.model(),t.effort());var reservation=budgets.reserve(t,cfg,model,65000,2048);assertThrows(IllegalStateException.class,()->budgets.reserve(t,cfg,model,65000,2048));assertEquals(67048,db.turn(t.id()).tokens());budgets.settle(t,reservation,200,500);budgets.settle(t,reservation,200,500);assertEquals(200,db.turn(t.id()).tokens());
 }
 @Test void organizationBudgetIsSharedAcrossUsers()throws Exception{
  var node=(ObjectNode)AssistantState.mapper().valueToTree(settings.get().settings());node.put("orgDailyTokens",100000);
  var cfg=settings.decode(node.toString());var first=claim(submit());var second=claim(db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"Read existing rules",null,null),"another"));
  var model=cfg.model(first.model(),first.effort());budgets.reserve(first,cfg,model,65000,2048);
  var failure=assertThrows(IllegalStateException.class,()->budgets.reserve(second,cfg,model,65000,2048));assertEquals("SHARED_BUDGET",failure.getMessage());assertEquals(0,db.turn(second.id()).tokens());
 }
 @Test void strictUnknownAndDuplicateToolArgumentsCannotExecute(){
  assertThrows(IllegalArgumentException.class,()->tools.invoke("engineer","shell","{}",1000));assertThrows(IllegalArgumentException.class,()->tools.invoke("engineer","search_rules","{\"query\":\"x\",\"offset\":0,\"path\":\"/etc/passwd\"}",1000));assertThrows(IllegalArgumentException.class,()->tools.invoke("engineer","search_rules","{\"query\":\"x\",\"query\":\"override\",\"offset\":0}",1000));assertThrows(IllegalArgumentException.class,()->tools.invoke("engineer","get_rule_health","{\"rule_id\":1,\"days\":900,\"scan_type\":\"all\"}",1000));
 }
 @Test void grantRevocationStopsRecoveryAndOldEvidenceReplay()throws Exception{
  var t=claim(submit());doThrow(new org.springframework.security.access.AccessDeniedException("revoked")).when(access).require("engineer","Assistant Use");LlmClient fake=r->{fail("No provider call after revocation");return null;};new AssistantTurnRunner(db,settings,tools,fake,budgets).run(t);assertEquals("ACCESS_REVOKED",db.turn(t.id()).error());
 }
 @Test void retentionUsesLastUserMessageAndHistoryReadsDoNotExtendExpiry()throws Exception{
  var t=submit();long expiry=((Number)db.session(t.session(),"engineer").get("expires_at")).longValue();db.history("engineer",0);db.conversation(t.session(),"engineer");assertEquals(expiry,((Number)db.session(t.session(),"engineer").get("expires_at")).longValue());
  database.jdbc.update("UPDATE assistant_sessions SET expires_at=0 WHERE session_id=?",t.session());assertThrows(ResponseStatusException.class,()->db.own(t,"engineer"));new AssistantMaintenance(db).maintain();new AssistantMaintenance(db).retain();assertNotNull(database.jdbc.queryForMap("SELECT transcript_purged_at FROM assistant_sessions WHERE session_id=?",t.session()).get("transcript_purged_at"));assertFalse(Files.exists(dir.resolve(t.checkpoint())));assertEquals("CANCELED",db.turn(t.id()).status());
 }
 @Test void deletionFailureCannotMarkTranscriptPurged()throws Exception{
  var t=submit();database.jdbc.update("UPDATE assistant_sessions SET expires_at=0 WHERE session_id=?",t.session());AssistantTranscriptStore failing=mock(AssistantTranscriptStore.class);when(failing.expire(anyString())).thenThrow(new IOException("unavailable"));var other=database.service(new AssistantPersistence(database.records,database.tx,failing,settings,access,accepted::add));new AssistantMaintenance(other).retain();assertNull(database.jdbc.queryForMap("SELECT transcript_purged_at FROM assistant_sessions WHERE session_id=?",t.session()).get("transcript_purged_at"));
 }
 @Test void oldUnpublishedArtifactIsReclaimedWithoutDeletingCurrentHistory()throws Exception{
  var t=submit();String orphan="assistant/conversations/"+t.session()+"/"+t.id()+"/"+UUID.randomUUID()+".json.gz";db.store().put(orphan,db.state(t).encode(1048576));
  database.jdbc.update("INSERT INTO assistant_artifacts (artifact_key,session_id,created_at,deleted_at) VALUES (?,?,0,NULL)",orphan,t.session());new AssistantMaintenance(db).maintain();new AssistantMaintenance(db).retain();
  assertFalse(Files.exists(dir.resolve(orphan)));assertTrue(Files.exists(dir.resolve(t.checkpoint())));assertEquals("Explain an existing rule",db.conversation(t.session(),"engineer").getFirst().get("text"));
 }
 @Test void titleIsTheFirstQuestionTidiedAndNeverASecret(){
  assertEquals("Why is this rule noisy?",AssistantPersistence.title("  Why   is this\nrule noisy?  "));
  String shortened=AssistantPersistence.title("Explain why the SQL injection rule for the Java scanner keeps matching safe prepared statements in tests");
  assertTrue(shortened.endsWith("..."));assertTrue(shortened.length()<=63);assertFalse(shortened.contains("  "));
  assertEquals("x".repeat(60)+"...",AssistantPersistence.title("x".repeat(100)));
  assertNull(AssistantPersistence.title("my password: hunter2 does this leak"));
  assertNull(AssistantPersistence.title("   "));assertNull(AssistantPersistence.title(null));
 }
 @Test void aNewChatIsListedUnderItsFirstQuestionAndALaterQuestionDoesNotRetitleIt()throws Exception{
  var first=submit();
  assertEquals("Explain an existing rule",db.history("engineer",0).getFirst().get("title"));
  var t=claim(first);db.terminal(t,"COMPLETED",null);
  db.submit(new AssistantPersistence.Submit(first.session(),UUID.randomUUID().toString(),"A completely different follow up",null,null),"engineer");
  assertEquals("Explain an existing rule",db.history("engineer",0).getFirst().get("title"));
 }
 @Test void reopeningReadsTheMessagesFromTheOneDecodedTranscript()throws Exception{
  var t=submit();
  var state=db.state(t);
  assertEquals(db.conversation(t.session(),"engineer"),AssistantPersistence.messages(state));
  assertEquals("Explain an existing rule",AssistantPersistence.messages(state).getFirst().get("text"));
 }
 @Test void deletingAChatRemovesItFromHistoryAndWritesAnAuditRow()throws Exception{
  var t=claim(submit());db.terminal(t,"COMPLETED",null);
  assertEquals(1,db.history("engineer",0).size());
  db.delete(t.session(),"engineer");
  assertTrue(db.history("engineer",0).isEmpty());
  assertThrows(ResponseStatusException.class,()->db.session(t.session(),"engineer"));
  assertEquals(1L,database.records.scalar(Long.class,"SELECT COUNT(*) FROM AssistantAuditEntity WHERE event=?1 AND sessionId=?2","CHAT_DELETED",t.session()));
 }
 @Test void aChatCanOnlyBeDeletedByItsOwnerAndNotWhileAnAnswerIsRunning()throws Exception{
  var running=submit();
  var busy=assertThrows(ResponseStatusException.class,()->db.delete(running.session(),"engineer"));
  assertEquals(org.springframework.http.HttpStatus.CONFLICT,busy.getStatusCode());
  var done=db.claim(running.id(),UUID.randomUUID().toString()).orElseThrow();db.terminal(done,"COMPLETED",null);
  var stranger=assertThrows(ResponseStatusException.class,()->db.delete(running.session(),"someone-else"));
  assertEquals(org.springframework.http.HttpStatus.NOT_FOUND,stranger.getStatusCode());
  assertEquals(1,db.history("engineer",0).size());
 }
 @Test void purgingADeletedChatRemovesItsStoredCopiesAndMarksItPurged()throws Exception{
  var t=claim(submit());db.terminal(t,"COMPLETED",null);String key=db.turn(t.id()).checkpoint();
  assertTrue(Files.exists(dir.resolve(key)));
  db.delete(t.session(),"engineer");new AssistantMaintenance(db).purgeSession(t.session());
  assertFalse(Files.exists(dir.resolve(key)));
  assertNotNull(database.records.find(com.tracelink.appsec.watchtower.core.persistence.AssistantSessionEntity.class,t.session()).transcriptPurgedAt);
 }
 @Test void aStorageFailureWhilePurgingLeavesTheCopyMarkedForTheDailyJob()throws Exception{
  var t=claim(submit());db.terminal(t,"COMPLETED",null);
  AssistantTranscriptStore failing=mock(AssistantTranscriptStore.class);when(failing.expire(anyString())).thenThrow(new IOException("unavailable"));
  var other=database.service(new AssistantPersistence(database.records,database.tx,failing,settings,access,accepted::add));
  db.delete(t.session(),"engineer");new AssistantMaintenance(other).purgeSession(t.session());
  assertNull(database.records.find(com.tracelink.appsec.watchtower.core.persistence.AssistantSessionEntity.class,t.session()).transcriptPurgedAt);
  new AssistantMaintenance(db).retain();
  assertNotNull(database.records.find(com.tracelink.appsec.watchtower.core.persistence.AssistantSessionEntity.class,t.session()).transcriptPurgedAt);
 }
 @Test void disabledFeatureAndDisallowedModelAreExplicit()throws Exception{
  var t=claim(submit());var node=(ObjectNode)AssistantState.mapper().valueToTree(settings.get().settings());node.put("defaultModel","another");node.putArray("allowedModels");node.put("enabled",false);settings.save(new AssistantSettingsService.Versioned(2,settings.decode(node.toString())),"admin");assertThrows(ResponseStatusException.class,db::enabled);assertThrows(IllegalArgumentException.class,()->settings.get().settings().model(t.model(),t.effort()));
 }
 @Test void sourceOwnershipAndInputLimitsAreChecked()throws Exception{
  var t=submit();assertThrows(ResponseStatusException.class,()->db.own(t,"another"));assertThrows(IllegalArgumentException.class,()->db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"x".repeat(16001),null,null),"another"));
 }
 @Test void refusalAndIncompleteResponseRemainVisible()throws Exception{
  var t=claim(submit());ArrayNode output=AssistantState.mapper().createArrayNode();output.addObject().put("type","message").putArray("content").addObject().put("type","refusal").put("refusal","I cannot provide that.");new AssistantTurnRunner(db,settings,tools,r->new LlmClient.Response(output,"completed",20,10,true),budgets).run(t);assertEquals("I cannot provide that.",db.state(db.turn(t.id())).answer);
  var next=claim(submit());new AssistantTurnRunner(db,settings,tools,r->new LlmClient.Response(answer("Partial").output(),"incomplete",20,10,true),budgets).run(next);assertTrue(db.state(db.turn(next.id())).answer.contains("Response incomplete"));
 }
}
