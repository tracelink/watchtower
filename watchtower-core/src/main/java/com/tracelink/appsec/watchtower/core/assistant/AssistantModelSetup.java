package com.tracelink.appsec.watchtower.core.assistant;

import java.io.IOException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import com.fasterxml.jackson.databind.node.*;

/** Explicit administrator setup works with Chat off; uses fixed synthetic data, never application evidence. */
@Service
public class AssistantModelSetup {
 public record Configure(long version,String model,String effort,int inputTokenLimit,int outputTokenLimit,
   long inputMicrosPerMillion,long outputMicrosPerMillion) { }
 private final AssistantSettingsService settings;private final AssistantAccess access;private final AssistantBudgetService budgets;private final OpenAiLlmClient client;
 public AssistantModelSetup(AssistantSettingsService settings,AssistantAccess access,AssistantBudgetService budgets,OpenAiLlmClient client){this.settings=settings;this.access=access;this.budgets=budgets;this.client=client;}
 public Object configure(Configure request,String owner){
  access.require(owner,"Assistant Admin");var stored=settings.get();if(stored.version()!=request.version())throw new ResponseStatusException(HttpStatus.CONFLICT,"Settings changed; reload before approving a model");
  var model=new AssistantSettings.Model(request.model(),List.of(request.effort()),request.inputTokenLimit(),request.outputTokenLimit(),request.inputMicrosPerMillion(),request.outputMicrosPerMillion(),LocalDate.now(ZoneOffset.UTC).toString(),"responses-synthetic-setup-v1");model.validate();
  var tree=(ObjectNode)AssistantState.mapper().valueToTree(stored.settings());ArrayNode allowed=tree.putArray("allowedModels");stored.settings().allowedModels().stream().filter(m->!m.id().equals(model.id())).forEach(m->allowed.add(AssistantState.mapper().valueToTree(m)));allowed.add(AssistantState.mapper().valueToTree(model));tree.put("defaultModel",model.id()).put("defaultEffort",request.effort());
  // Validate all configured limits without changing the existing Chat or other feature switches.
  var proposed=settings.decode(tree.toString());if(proposed.maxOutputTokens()>model.outputTokenLimit())throw new IllegalArgumentException("Model output allowance must cover the configured answer limit");
  long tokens=(long)model.inputTokenLimit()+proposed.maxOutputTokens(),cost=model.cost(model.inputTokenLimit(),proposed.maxOutputTokens());
  if(tokens>proposed.turnTokenCap()||tokens>proposed.userDailyTokens()||tokens>proposed.orgDailyTokens()||cost>proposed.turnCostMicros()||cost>proposed.userDailyCostMicros()||cost>proposed.orgDailyCostMicros())throw new IllegalArgumentException("The selected model allowance exceeds the configured token or cost caps");
  try {
   access.require(owner,"Assistant Admin");if(!client.discover().contains(model.id()))throw new IllegalArgumentException("This account cannot access the selected model");
   probe(owner,proposed,model);
  }catch(InterruptedException e){Thread.currentThread().interrupt();throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Model validation was interrupted; no model was approved");}
  catch(IOException e){throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"The synthetic Responses compatibility check failed; no model was approved. Check model, effort and provider status");}
  access.require(owner,"Assistant Admin");settings.save(new AssistantSettingsService.Versioned(request.version(),proposed),owner);
  return Map.of("status","APPROVED","model",model.id(),"message","Synthetic tool round-trip and structured output passed. Default model saved. Chat and rollout settings are unchanged; complete answer-quality evaluation before broader activation.");
 }
 private void probe(String owner,AssistantSettings cfg,AssistantSettings.Model model)throws IOException,InterruptedException {
  var input=AssistantState.mapper().createArrayNode();input.addObject().put("role","user").put("content","Call read_compatibility_marker exactly once with {}. Wait for its result, then reply with that marker only. This is a synthetic provider compatibility check.");
  var tools=AssistantState.mapper().createArrayNode();var tool=tools.addObject().put("type","function").put("name","read_compatibility_marker").put("description","Read a fixed synthetic marker; no application access.").put("strict",true);tool.putObject("parameters").put("type","object").put("additionalProperties",false).putObject("properties");((ObjectNode)tool.path("parameters")).putArray("required");
  var first=call(owner,cfg,model,input,tools);
  var calls=new ArrayList<com.fasterxml.jackson.databind.JsonNode>();first.output().forEach(i->{if("function_call".equals(i.path("type").asText()))calls.add(i);});
  if(!"completed".equals(first.status())||calls.size()!=1||!"read_compatibility_marker".equals(calls.getFirst().path("name").asText())||!AssistantState.mapper().readTree(calls.getFirst().path("arguments").asText()).equals(AssistantState.mapper().createObjectNode()))throw new IOException("Tool protocol rejected");
  first.output().forEach(input::add);input.addObject().put("type","function_call_output").put("call_id",calls.getFirst().path("call_id").asText()).put("output","WATCHTOWER_SYNTHETIC_OK");
  var second=call(owner,cfg,model,input,tools);if(!"completed".equals(second.status())||!AssistantTurnRunner.text(second.output()).contains("WATCHTOWER_SYNTHETIC_OK"))throw new IOException("Tool replay rejected");
  var schema=AssistantState.mapper().createObjectNode().put("type","object").put("additionalProperties",false);schema.putObject("properties").putObject("ok").put("type","boolean");schema.putArray("required").add("ok");
  access.require(owner,"Assistant Admin");var charge=reserve(owner,cfg,model,4096);var reply=client.structured(new OpenAiLlmClient.Structured(model.id(),model.efforts().getFirst(),"Synthetic compatibility check. Return ok true.","No repository, rule, finding or personal data is supplied.","watchtower_model_setup",schema,Math.min(2048,cfg.maxOutputTokens()),cfg.providerTimeoutSeconds(),AssistantPersistence.ownerKey(owner)));
  if(reply.usageKnown())budgets.settleDirect(charge,Math.min(charge.tokens(),reply.inputTokens()+reply.outputTokens()),Math.min(charge.cost(),model.cost(reply.inputTokens(),reply.outputTokens())));
  if(!"completed".equals(reply.status())||reply.refused()||!AssistantState.mapper().readTree(reply.text()).path("ok").asBoolean())throw new IOException("Structured output rejected");
 }
 private LlmClient.Response call(String owner,AssistantSettings cfg,AssistantSettings.Model model,ArrayNode input,ArrayNode tools)throws IOException,InterruptedException {
  access.require(owner,"Assistant Admin");int bound=AssistantState.mapper().writeValueAsBytes(input).length+AssistantState.mapper().writeValueAsBytes(tools).length+4096;
  var charge=reserve(owner,cfg,model,bound);var response=client.complete(new LlmClient.Request(model.id(),model.efforts().getFirst(),input,tools,Math.min(2048,cfg.maxOutputTokens()),cfg.providerTimeoutSeconds(),AssistantPersistence.ownerKey(owner),"r1-v1"));
  if(response.usageKnown())budgets.settleDirect(charge,Math.min(charge.tokens(),response.inputTokens()+response.outputTokens()),Math.min(charge.cost(),model.cost(response.inputTokens(),response.outputTokens())));return response;
 }
 private AssistantBudgetService.Charge reserve(String owner,AssistantSettings cfg,AssistantSettings.Model model,long bound){
  if(bound>model.inputTokenLimit())throw new IllegalArgumentException("Model input allowance is too small for a synthetic compatibility check");
  try{return budgets.reserveDirect(owner,cfg,model,bound,Math.min(2048,cfg.maxOutputTokens()));}catch(IllegalStateException e){throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"The AI budget cannot cover model validation right now");}
 }
}
