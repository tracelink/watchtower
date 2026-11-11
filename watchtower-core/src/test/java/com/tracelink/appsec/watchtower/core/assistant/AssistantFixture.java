package com.tracelink.appsec.watchtower.core.assistant;

import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;
import com.tracelink.appsec.watchtower.core.rule.RuleReviewService;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;

/** Chat-ready assistant services over the in-memory database, with a $1 / $2 per million token model. */
final class AssistantFixture implements AutoCloseable {
 final R1Database database=new R1Database();
 final AtomicBoolean keyConfigured=new AtomicBoolean(true);
 final AssistantSettingsService settings;
 final AssistantAccess access=mock(AssistantAccess.class);
 final AssistantPersistence db;
 final AssistantBudgetService budgets;
 final AssistantToolRegistry tools;
 final List<Object> accepted=new ArrayList<>();
 final RuleService rules=mock(RuleService.class);

 AssistantFixture(Path transcripts,Set<String> grants)throws Exception{
  settings=database.service(new AssistantSettingsService(database.records,R1Database.keys(keyConfigured),null,false));
  when(access.authorities(anyString())).thenReturn(grants);
  var rulesets=mock(RulesetService.class);when(rules.getRules()).thenReturn(List.of());when(rulesets.getRulesets()).thenReturn(List.of());
  tools=database.service(new AssistantToolRegistry(access,rules,rulesets,new RuleHealthService(database.records,6,3,.5),mock(RuleReviewService.class),database.records,mock(AssistantSourceTools.class),mock(AssistantSecretFindings.class)));
  db=database.service(new AssistantPersistence(database.records,database.tx,new LocalAssistantTranscriptStore(transcripts),settings,access,accepted::add));
  budgets=database.service(new AssistantBudgetService(database.records,database.tx));
  configure(c->{ });
 }
 /** Saves chat-ready settings, then applies the change; validation failures propagate. */
 void configure(Consumer<ObjectNode> change)throws Exception{
  var current=settings.get();var config=(ObjectNode)AssistantState.mapper().valueToTree(current.settings());
  config.put("enabled",true).put("defaultModel","fixture-model").put("defaultEffort","low");
  config.putArray("allowedModels").addObject().put("id","fixture-model").put("inputTokenLimit",65536).put("outputTokenLimit",8192).put("inputMicrosPerMillion",1000000).put("outputMicrosPerMillion",2000000)
   .put("validatedAt","2026-10-10").put("validationRef","fixture:responses-v1").putArray("efforts").add("low");
  change.accept(config);
  settings.save(new AssistantSettingsService.Versioned(current.version(),settings.decode(config.toString())),"admin");
 }
 /** Turns on one feature with its daily slice. */
 static void slice(ObjectNode config,String feature,boolean on,long tokens,long cost){
  var features=config.has("features")&&config.get("features").isObject()?(ObjectNode)config.get("features"):config.putObject("features");
  (features.has("enabled")?(ObjectNode)features.get("enabled"):features.putObject("enabled")).put(feature,on);
  (features.has("slices")?(ObjectNode)features.get("slices"):features.putObject("slices")).putObject(feature).put("dailyTokens",tokens).put("dailyCostMicros",cost);
 }
 AssistantSettings cfg(){return settings.get().settings();}
 AssistantSettings.Model model(){return cfg().model("fixture-model","low");}
 AssistantPersistence.Turn claim(String owner,String message)throws Exception{
  var turn=db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),message,null,null),owner);
  return db.claim(turn.id(),UUID.randomUUID().toString()).orElseThrow();
 }
 static LlmClient.Response answer(String text){
  ArrayNode output=AssistantState.mapper().createArrayNode();
  output.addObject().put("type","message").put("role","assistant").putArray("content").addObject().put("type","output_text").put("text",text);
  return new LlmClient.Response(output,"completed",10,5,true);
 }
 static LlmClient.Response toolCall(String name,String arguments){
  ArrayNode output=AssistantState.mapper().createArrayNode();
  output.addObject().put("type","function_call").put("name",name).put("call_id","call_1").put("arguments",arguments);
  return new LlmClient.Response(output,"completed",10,5,true);
 }
 @Override public void close(){database.close();}
}
