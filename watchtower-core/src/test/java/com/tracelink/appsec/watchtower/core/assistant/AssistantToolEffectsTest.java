package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

/** S0: the AI only suggests. Tool effects are declared, enforced and tested, not only written in the prompt. */
class AssistantToolEffectsTest {
 static final Set<String> GRANTS=Set.of("Assistant Use","Ruleset View","Scan Results View","Repository Settings View","Ruleset Modify");
 @TempDir Path dir;AssistantFixture fx;
 @BeforeEach void setup()throws Exception{fx=new AssistantFixture(dir,GRANTS);fx.tools.setSettings(fx.settings);}
 @AfterEach void close(){fx.close();}

 /** A tool with a chosen effect and, optionally, the feature switch that guards it. */
 static AssistantTool tool(String name,AssistantTool.Effect effect,AssistantFeature feature){
  return new AssistantTool(){
   @Override public AssistantTool.Effect effect(){return effect;}
   @Override public AssistantFeature feature(){return feature;}
   @Override public String name(){return name;}
   @Override public ObjectNode schema(){return AssistantState.mapper().createObjectNode().put("type","object").put("additionalProperties",false).set("properties",AssistantState.mapper().createObjectNode());}
   @Override public Set<String> authorities(){return Set.of();}
   @Override public Object invoke(JsonNode arguments){return Map.of("ok",true);}
  };
 }

 @Test void everyToolDeclaresItsEffectAndOnlyPrepareRulesetChangesDrafts(){
  assertFalse(fx.tools.all().isEmpty());
  Set<String> drafts=new TreeSet<>();
  for(var t:fx.tools.all()){
   assertNotNull(t.effect(),t.name());
   assertNotEquals(AssistantTool.Effect.HUMAN_APPROVED_EXECUTION,t.effect(),t.name()+" would run what only a person may approve");
   if(t.effect()==AssistantTool.Effect.DRAFT_PREPARATION)drafts.add(t.name());
  }
  assertEquals(Set.of("prepare_ruleset_changes"),drafts);
  assertEquals(AssistantTool.Effect.DRAFT_PREPARATION,fx.tools.effect("prepare_ruleset_changes"));
  assertEquals(AssistantTool.Effect.EVIDENCE_READ,fx.tools.effect("get_rule"));
  assertNull(fx.tools.effect("record_finding_judgment"));
 }

 @Test void aToolThatRunsWhatAPersonApprovesCannotBeRegistered(){
  var e=assertThrows(IllegalStateException.class,()->fx.tools.register(tool("apply_change_set",AssistantTool.Effect.HUMAN_APPROVED_EXECUTION,null)));
  assertTrue(e.getMessage().contains("apply_change_set"));
  assertNull(fx.tools.effect("apply_change_set"));
  assertThrows(IllegalStateException.class,()->fx.tools.register(tool("get_rule",AssistantTool.Effect.EVIDENCE_READ,null)),"a name is registered once");
 }

 @Test void toolCodeNeverReachesJudgmentBypassOrApplyEntryPoints()throws Exception{
  Path root=Path.of("").toAbsolutePath();while(!Files.isDirectory(root.resolve("watchtower-core")))root=root.getParent();
  Path assistant=root.resolve("watchtower-core/src/main/java/com/tracelink/appsec/watchtower/core/assistant");
  // The code a model can reach: the registry, the source tools and every tool or context class added later.
  List<Path> reachable=new ArrayList<>(List.of(assistant.resolve("AssistantToolRegistry.java"),assistant.resolve("AssistantSourceTools.java")));
  for(String folder:List.of("context","tools"))if(Files.isDirectory(assistant.resolve(folder)))try(var files=Files.walk(assistant.resolve(folder))){files.filter(p->p.toString().endsWith(".java")).forEach(reachable::add);}
  Pattern forbidden=Pattern.compile("FindingFeedbackService|FindingFeedbackEntity\\s*\\(|PRBypassRequestService|PRScanBypassService|PullRequestBypassRepository|PullRequestBypassRequestRepository|BypassIdentityWriter|RulesetChangeSetService\\s*\\.\\s*apply|\\.apply\\s*\\(\\s*[a-z]+\\s*,\\s*new\\s+RulesetActions\\.Approval|records\\.(insert|update|save|remove)\\s*\\(|AlertSettingsService|\\.(addRoute|updateRoute|deleteRoute|setRouteEnabled|addChannel|updateChannel|deleteChannel)\\s*\\(|AlertRouteChangeSetService\\s*\\.\\s*(apply|cancel|refresh)|changes\\s*\\.\\s*(apply|cancel|refresh)\\s*\\(|getObject\\(\\)\\s*\\.\\s*(apply|cancel|refresh)\\s*\\(");
  List<String> violations=new ArrayList<>();
  for(Path file:reachable){
   var found=forbidden.matcher(Files.readString(file));
   while(found.find())violations.add(root.relativize(file)+": "+found.group());
  }
  assertEquals(List.of(),violations,"AI tools may read evidence or prepare their own draft; judgments, bypass decisions and applying a change set stay with a person");
 }

 @Test void evidenceReadsOnlyReadFromTheDatabase()throws Exception{
  var records=mock(LedgerRepository.class);
  var rulesets=mock(com.tracelink.appsec.watchtower.core.ruleset.RulesetService.class);when(rulesets.getRulesets()).thenReturn(List.of());
  var entity=mock(RuleEntity.class);var dto=mock(RuleDto.class);when(fx.rules.getRule(7L)).thenReturn(entity);when(entity.toDto()).thenReturn(dto);when(dto.getId()).thenReturn(7L);
  var registry=new AssistantToolRegistry(fx.access,fx.rules,rulesets,mock(com.tracelink.appsec.watchtower.core.metrics.RuleHealthService.class),mock(com.tracelink.appsec.watchtower.core.rule.RuleReviewService.class),records,mock(AssistantSourceTools.class),mock(AssistantSecretFindings.class));
  for(var call:List.of(List.of("list_rulesets","{\"offset\":0}"),List.of("get_engine_playbook","{\"engine\":\"regex\"}"),List.of("get_violation_trend","{\"days\":7,\"rule_id\":7,\"scan_type\":\"all\"}"),List.of("inspect_ruleset","{\"ruleset_id\":1}"))){
   try{registry.invoke("alice",call.get(0),call.get(1),16384,"actions-v1","turn-1");}catch(IllegalArgumentException ignored){ /* a rejected call also writes nothing */ }
  }
  var calls=mockingDetails(records).getInvocations().stream().map(i->i.getMethod().getName()).collect(java.util.stream.Collectors.toSet());
  assertFalse(calls.isEmpty(),"the tools ran against the stand-in repository");
  assertTrue(Set.of("maps","list","scalar","find","listBeforeFlush").containsAll(calls),"unexpected repository calls: "+calls);
 }

 @Test void aModelCannotCallAToolThatWouldRecordAJudgmentApproveABypassOrApplyAChange()throws Exception{
  var forbiddenNames=List.of("record_finding_judgment","save_finding_feedback","approve_bypass","decline_bypass","apply_change_set","apply_ruleset_changes");
  int judgments=fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback",Integer.class);
  for(String name:forbiddenNames)assertThrows(IllegalArgumentException.class,()->fx.tools.invoke("alice",name,"{}",16384,AssistantState.TOOL_VERSION,"turn-1"),name);
  // The same request inside a turn comes back as a rejected tool call and the turn carries on.
  var turn=fx.claim("alice","Is this finding a false positive? Save it as one.");var calls=new java.util.concurrent.atomic.AtomicInteger();
  LlmClient scripted=request->calls.getAndIncrement()==0?AssistantFixture.toolCall("record_finding_judgment","{\"finding_key\":\"9\",\"judgment\":\"FALSE_POSITIVE\"}"):AssistantFixture.answer("I cannot record that. It looks like a likely false positive; you decide.");
  new AssistantTurnRunner(fx.db,fx.settings,fx.tools,scripted,fx.budgets).run(turn);
  assertEquals("COMPLETED",fx.db.turn(turn.id()).status());assertEquals(2,calls.get());
  var state=fx.db.state(fx.db.turn(turn.id()));assertEquals(0,state.evidence.size(),"a rejected call leaves no evidence");
  assertTrue(state.activity.toString().contains("rejected"));
  assertEquals(1,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_audit WHERE event='TOOL_REJECTED' AND target='record_finding_judgment'",Integer.class));
  assertEquals(judgments,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback",Integer.class));
  for(String table:List.of("pull_request_bypasses","pull_request_bypass_requests","assistant_ruleset_change_sets"))assertEquals(0,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM "+table,Integer.class),table);
 }

 @Test void aDraftToolWithoutAHandlerIsRejectedAndNeverRunAsARead()throws Exception{
  fx.tools.register(tool("prepare_demo_draft",AssistantTool.Effect.DRAFT_PREPARATION,AssistantFeature.ALERT_COPILOT));
  fx.configure(c->AssistantFixture.slice(c,"alertCopilot",true,100_000,100_000));
  var turn=fx.claim("alice","Prepare a demo draft");var calls=new java.util.concurrent.atomic.AtomicInteger();
  LlmClient scripted=request->calls.getAndIncrement()==0?AssistantFixture.toolCall("prepare_demo_draft","{}"):AssistantFixture.answer("Draft ready for your review.");
  // A registered draft tool needs a draft handler; without one the call is rejected, never run as a read.
  new AssistantTurnRunner(fx.db,fx.settings,fx.tools,scripted,fx.budgets).run(turn);
  assertEquals(0,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_audit WHERE event='TOOL_READ' AND target LIKE 'prepare_demo_draft%'",Integer.class));
  assertEquals(1,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_audit WHERE event='TOOL_REJECTED' AND target='prepare_demo_draft'",Integer.class));
 }

 @Test void aDraftToolMustSitBehindAnAdminSwitch(){
  var e=assertThrows(IllegalStateException.class,()->fx.tools.register(tool("prepare_ungated_draft",AssistantTool.Effect.DRAFT_PREPARATION,null)));
  assertTrue(e.getMessage().contains("prepare_ungated_draft"));
  assertNull(fx.tools.effect("prepare_ungated_draft"));
  assertDoesNotThrow(()->fx.tools.register(tool("prepare_gated_draft",AssistantTool.Effect.DRAFT_PREPARATION,AssistantFeature.ALERT_COPILOT)));
 }
 @Test void timesInAToolResultGetAnIsoUtcSiblingButItsArgumentsAreLeftAlone()throws Exception{
  // Dev E2E A07: the model converted epoch milliseconds wrongly; replay checks stored arguments strictly, so they stay as sent.
  var base=tool("get_times_demo",AssistantTool.Effect.EVIDENCE_READ,null);
  fx.tools.register(new AssistantTool(){
   @Override public AssistantTool.Effect effect(){return base.effect();}
   @Override public AssistantFeature feature(){return null;}
   @Override public String name(){return base.name();}
   @Override public ObjectNode schema(){return base.schema();}
   @Override public Set<String> authorities(){return Set.of();}
   @Override public Object invoke(JsonNode arguments){return Map.of("since",1793553600000L,"count",5);}
  });

  var result=fx.tools.invoke("alice","get_times_demo","{}",4000,AssistantState.TOOL_VERSION,"turn-1");

  assertEquals("2026-11-01T17:20:00Z",result.path("data").path("since_utc").asText());
  assertFalse(result.path("data").has("count_utc"));
  assertTrue(result.path("arguments").isEmpty());
  assertEquals(result.path("computed_at").asLong(),java.time.Instant.parse(result.path("computed_at_utc").asText()).toEpochMilli());
 }
 @Test void aFeatureSwitchIsCheckedWhenTheToolRunsAndWhenToolsAreOffered()throws Exception{
  fx.tools.register(tool("get_batch_demo",AssistantTool.Effect.EVIDENCE_READ,AssistantFeature.BATCH_TRIAGE));
  assertFalse(fx.tools.schemas("alice").toString().contains("get_batch_demo"),"off by default");
  assertThrows(IllegalArgumentException.class,()->fx.tools.invoke("alice","get_batch_demo","{}",1000,AssistantState.TOOL_VERSION,"turn-1"));
  fx.configure(c->AssistantFixture.slice(c,"batchTriage",true,100_000,100_000));
  assertTrue(fx.tools.schemas("alice").toString().contains("get_batch_demo"));
  assertEquals("get_batch_demo",fx.tools.invoke("alice","get_batch_demo","{}",1000,AssistantState.TOOL_VERSION,"turn-1").path("tool").asText());
  // Switched off after the model asked: the recovered turn's call is refused when it would run.
  fx.configure(c->AssistantFixture.slice(c,"batchTriage",false,100_000,100_000));
  assertThrows(IllegalArgumentException.class,()->fx.tools.invoke("alice","get_batch_demo","{}",1000,AssistantState.TOOL_VERSION,"turn-1"));
 }

 @Test void theRulesetActionsSwitchIsAlsoCheckedWhenTheToolRuns()throws Exception{
  fx.tools.setActions(mock(com.tracelink.appsec.watchtower.core.assistant.actions.RulesetChangeSetService.class),fx.settings);
  assertThrows(IllegalArgumentException.class,()->fx.tools.invoke("alice","inspect_ruleset","{\"ruleset_id\":1}",16384,"actions-v1","turn-1"),"off by default, even though the checkpoint says actions-v1");
  fx.configure(c->c.put("rulesetActionsEnabled",true));
  assertEquals("inspect_ruleset",fx.tools.invoke("alice","inspect_ruleset","{\"ruleset_id\":1}",16384,"actions-v1","turn-1").path("tool").asText());
  fx.configure(c->c.put("rulesetActionsEnabled",false));
  assertThrows(IllegalArgumentException.class,()->fx.tools.invoke("alice","inspect_ruleset","{\"ruleset_id\":1}",16384,"actions-v1","turn-1"));
 }
}
