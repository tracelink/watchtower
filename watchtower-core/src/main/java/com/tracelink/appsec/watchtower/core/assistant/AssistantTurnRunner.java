package com.tracelink.appsec.watchtower.core.assistant;

import java.util.*;
import java.io.*;
import java.util.concurrent.ThreadLocalRandom;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import org.springframework.stereotype.Service;
import org.springframework.security.access.AccessDeniedException;

/** Every model response/tool result is checkpointed before proceeding. R1 has no write tools. */
@Service
public class AssistantTurnRunner {
 private com.tracelink.appsec.watchtower.core.rule.improvement.RuleImprovementService improvements;
 @org.springframework.beans.factory.annotation.Autowired
 public void setImprovements(com.tracelink.appsec.watchtower.core.rule.improvement.RuleImprovementService improvements){this.improvements=improvements;}
 private void authorizeTask(AssistantPersistence.Turn t,AssistantState s){if(s.taskKind!=null){if(improvements==null)throw new IllegalStateException("RECOVERY_CONFIGURATION");improvements.authorizeTask(t,s);}}
 private void finish(AssistantPersistence.Turn t,AssistantState s,String text)throws IOException{if(s.taskKind!=null)improvements.complete(t,s,text);s.finish(text);
  // Recorded before the answer is published, so no answer can be seen without its exposure on record.
  recordExposure(t,s);db.checkpoint(t,s,true);}
 private com.tracelink.appsec.watchtower.core.assistant.context.ContextService contexts;
 @org.springframework.beans.factory.annotation.Autowired(required=false)
 public void setContexts(com.tracelink.appsec.watchtower.core.assistant.context.ContextService contexts){this.contexts=contexts;}
 private com.tracelink.appsec.watchtower.core.assistant.assessment.FindingAiExposures exposures;
 @org.springframework.beans.factory.annotation.Autowired(required=false)
 public void setExposures(com.tracelink.appsec.watchtower.core.assistant.assessment.FindingAiExposures exposures){this.exposures=exposures;}
 /** Findings a person may have heard an AI opinion about: the page's finding, and any finding a read tool looked at. */
 private void recordExposure(AssistantPersistence.Turn t,AssistantState s){
  if(exposures==null||s.taskKind!=null)return;
  Set<String> keys=new LinkedHashSet<>();
  var card=s.card();
  if(card!=null&&card.isOk()&&"finding".equals(card.kind())&&card.ids().get("scanId") instanceof Number id&&card.ids().get("findingKey") instanceof String key&&card.ids().get("scanType") instanceof String type)
   keys.add(com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService.occurrenceKey(type,id.longValue(),key));
  for(var e:s.evidence){
   if(!Set.of("get_finding","get_finding_assessment").contains(e.path("name").asText()))continue;
   var a=e.path("arguments");
   if(a.path("scan_id").canConvertToLong())keys.add(com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService.occurrenceKey(a.path("scan_type").asText(),a.path("scan_id").asLong(),a.path("finding_key").asText()));
  }
  for(String key:keys)exposures.record(key,t.owner(),com.tracelink.appsec.watchtower.core.assistant.assessment.FindingAiExposures.CHAT);
 }
 /** Compared as text read back, so a stored 1 and a rebuilt 1L are the same number. */
 static boolean sameCard(com.tracelink.appsec.watchtower.core.assistant.context.ContextCard fresh,JsonNode stored){
  try{return AssistantState.mapper().readTree(AssistantState.mapper().writeValueAsString(fresh)).equals(stored);}
  catch(com.fasterxml.jackson.core.JsonProcessingException e){return false;}
 }
 static final Set<String> FINDING_TOOLS=Set.of("get_finding","get_finding_assessment");
 static final int MAX_STALE_CHECKS=10;
 static final String BLOCKED_TOOL_DATA="{\"blocked\":\"secret finding\"}";
 /**
  * Tool output kept from earlier turns about a finding that has since become secret is replaced by the
  * marker before anything is sent. A finding that cannot be checked, or beyond the first ten, is replaced too.
  */
 private void scrubStaleFindings(AssistantPersistence.Turn t,AssistantState s)throws IOException{
  if(contexts==null)return;
  Map<String,Boolean> blocked=new HashMap<>();boolean changed=false;
  for(var item:s.protocol){
   if(!"function_call_output".equals(item.path("type").asText()))continue;
   JsonNode out;try{out=AssistantState.mapper().readTree(item.path("output").asText());}catch(IOException|RuntimeException e){continue;}
   if(!FINDING_TOOLS.contains(out.path("tool").asText())||out.path("data").path("blocked").isTextual())continue;
   var a=out.path("arguments");String key=a.path("scan_type").asText()+"|"+a.path("scan_id").asText()+"|"+a.path("finding_key").asText();
   Boolean isBlocked=blocked.get(key);
   if(isBlocked==null){
    isBlocked=blocked.size()>=MAX_STALE_CHECKS||contexts.findingIsBlockedNow(new com.tracelink.appsec.watchtower.core.assistant.context.ContextRequest.Ids(a.path("scan_type").asText(),a.path("scan_id").asLong(),a.path("finding_key").asText(),null,null));
    blocked.put(key,isBlocked);
   }
   if(isBlocked){
    ((ObjectNode)item).put("output",AssistantState.mapper().createObjectNode().put("tool",out.path("tool").asText()).put("data_is_untrusted",true).set("data",AssistantState.mapper().readTree(BLOCKED_TOOL_DATA)).toString());changed=true;
   }
  }
  if(changed)db.checkpoint(t,s,false);
 }
 /** What a blocked finding is answered with, without any model call. */
 public static final String BLOCKED_ANSWER="Blocked: secret finding. Findings of secret rules are never sent to the AI.";
 /**
  * Checks the page card again for this person before it is used: revoked access stops the turn, and a
  * card that is now blocked ends it with the fixed answer and no model call. Returns true when it ended the turn.
  */
 private boolean contextEndsTurn(AssistantPersistence.Turn t,AssistantState s)throws IOException{
  var stored=s.card();if(stored==null||contexts==null)return false;
  var fresh=contexts.revalidate(t.owner(),stored);
  if(!sameCard(fresh,s.context)){s.useContext(fresh);db.checkpoint(t,s,false);}
  if(!fresh.isBlocked())return false;
  db.audit(t.owner(),t.session(),t.id(),"CONTEXT_BLOCKED",fresh.kind(),t.model(),t.effort(),0,0);
  finish(t,s,BLOCKED_ANSWER);return true;
 }
 private final AssistantPersistence db;private final AssistantSettingsService settings;
 private final AssistantToolRegistry tools;private final LlmClient client;private final AssistantBudgetService budgets;
 public AssistantTurnRunner(AssistantPersistence db,AssistantSettingsService settings,AssistantToolRegistry tools,LlmClient client,AssistantBudgetService budgets){this.db=db;this.settings=settings;this.tools=tools;this.client=client;this.budgets=budgets;}
 public void run(AssistantPersistence.Turn turn){
  try {
   var cfg=settings.decode(turn.settingsJson());var model=cfg.model(turn.model(),turn.effort());var state=db.state(turn);
   if(!turn.model().equals(state.model)||!turn.effort().equals(state.effort))throw new IllegalStateException("RECOVERY_CONFIGURATION");
   tools.replay(turn.owner(),state);authorizeTask(turn,state);
   // Once per run, so a recovered turn on another pod checks the page again, without a database round trip per model call.
   if(state.answer==null){scrubStaleFindings(turn,state);if(contextEndsTurn(turn,state))return;}
   while(state.answer==null) {
    db.check(turn);tools.replay(turn.owner(),state);authorizeTask(turn,state);
    if(state.pendingAnswer!=null){finish(turn,state,state.pendingAnswer);return;}
    List<JsonNode> pending=pending(state.protocol);
    if(!pending.isEmpty()) {
     for(var call:pending) {
      db.check(turn);if(state.toolCalls>=12){completeLimit(turn,state,"Tool call limit reached. The available evidence is retained in this conversation.");return;}
      state.toolCalls++;String name=call.path("name").asText(),args=call.path("arguments").asText();ObjectNode result;
      try {result=tools.invoke(turn.owner(),name,args,cfg.maxToolBytes(),state.toolVersion,turn.id());
       var evidence=state.evidence.addObject().put("name",name);evidence.set("arguments",result.get("arguments"));
       if(result.path("data").has("requiredPermissions"))evidence.set("required_grants",result.path("data").get("requiredPermissions"));
       db.audit(turn.owner(),turn.session(),turn.id(),tools.effect(name)==AssistantTool.Effect.DRAFT_PREPARATION?"DRAFT_PREPARED":"TOOL_READ",name+":"+result.path("arguments").path("rule_id").asText("scope")+":"+result.path("data").path("revision").asText("unknown"),turn.model(),turn.effort(),0,0);
      } catch(IllegalArgumentException e){result=AssistantState.mapper().createObjectNode().put("error","Tool unavailable or arguments rejected. Use the strict authorized schema.");db.audit(turn.owner(),turn.session(),turn.id(),"TOOL_REJECTED",name.matches("[a-z_]{1,64}")?name:"unknown",turn.model(),turn.effort(),0,0);}
      state.protocol.addObject().put("type","function_call_output").put("call_id",call.path("call_id").asText()).put("output",AssistantState.mapper().writeValueAsString(result));
      var step=state.activity.addObject().put("tool",name.matches("[a-z_]{1,64}")?name:"unknown").put("status",result.has("error")?"rejected":tools.effect(name)==AssistantTool.Effect.DRAFT_PREPARATION?"prepared":"read");
      // The rule a successful read used, so the answer can cite it as a chip.
      if(!result.has("error")&&result.path("arguments").path("rule_id").canConvertToLong())step.put("rule",result.path("arguments").path("rule_id").asLong());
      // Whether the assessment tool returned an AI assessment at all, so "AI opinion seen" is only said when one was.
      if("get_finding_assessment".equals(name)&&!result.has("error"))step.put("opinion","ASSESSED".equals(result.path("data").path("state").asText()));
      db.checkpoint(turn,state,false);
     }
     continue;
    }
    if(state.iterations>=cfg.maxIterations()){completeLimit(turn,state,"Model iteration limit reached. Narrow the question or continue with the evidence already collected.");return;}
    var schemas=tools.schemas(turn.owner(),state.toolVersion);var request=new LlmClient.Request(turn.model(),turn.effort(),state.protocol.deepCopy(),schemas,cfg.maxOutputTokens(),cfg.providerTimeoutSeconds(),AssistantPersistence.ownerKey(turn.owner()),state.promptVersion);
    long input=AssistantState.mapper().writeValueAsBytes(OpenAiLlmClient.payload(request)).length;
    // A large tool catalog can crowd out the final answer after evidence has been read.
    // Retry the same authorized protocol without offering more tools; every existing cap still applies.
    if((input>cfg.maxInputBytes()||input>model.inputTokenLimit())&&state.toolCalls>0&&!schemas.isEmpty()){
     var finalRequest=new LlmClient.Request(turn.model(),turn.effort(),state.protocol.deepCopy(),AssistantState.mapper().createArrayNode(),cfg.maxOutputTokens(),cfg.providerTimeoutSeconds(),AssistantPersistence.ownerKey(turn.owner()),state.promptVersion);
     long finalInput=AssistantState.mapper().writeValueAsBytes(OpenAiLlmClient.payload(finalRequest)).length;
     if(finalInput<=cfg.maxInputBytes()&&finalInput<=model.inputTokenLimit()){
      request=finalRequest;input=finalInput;db.audit(turn.owner(),turn.session(),turn.id(),"LIMIT_REACHED","Final answer using collected evidence; further tools unavailable",turn.model(),turn.effort(),0,0);
     }
    }
    if(input>cfg.maxInputBytes()||input>model.inputTokenLimit()){completeLimit(turn,state,"Conversation input limit reached. Start a new conversation or narrow the question.");return;}
    LlmClient.Response response=null;
    for(int attempt=0;attempt<3;attempt++) {
     db.check(turn);tools.replay(turn.owner(),state);authorizeTask(turn,state);
     var reservation=budgets.reserve(turn,cfg,model,model.inputTokenLimit(),cfg.maxOutputTokens());
     // Reservation survives a crash/provider uncertainty; retry consumes another reservation.
     db.audit(turn.owner(),turn.session(),turn.id(),"PROVIDER_ATTEMPT",reservation.id(),turn.model(),turn.effort(),reservation.tokens(),reservation.cost());
     try {response=client.complete(request);if(response.usageKnown())budgets.settle(turn,reservation,response.inputTokens()+response.outputTokens(),model.cost(response.inputTokens(),response.outputTokens()));break;}
     catch(LlmClient.ProviderFailure e){
      if(!e.retryable()||attempt==2)throw e;
      db.audit(turn.owner(),turn.session(),turn.id(),"PROVIDER_RETRY",e.code(),turn.model(),turn.effort(),0,0);
      long delay=Math.max(e.retryAfterMillis(),(1L<<attempt)*500+ThreadLocalRandom.current().nextLong(250));
      if(System.currentTimeMillis()+delay>=turn.deadline())throw new IllegalStateException("TURN_DEADLINE");Thread.sleep(Math.min(delay,30000));
     }
    }
    if(response==null)throw new IllegalStateException("PROVIDER_PROTOCOL");db.check(turn);
    if(request.tools().isEmpty()&&response.output().findValues("type").stream().anyMatch(v->"function_call".equals(v.asText())))throw new IllegalStateException("PROVIDER_PROTOCOL");
    append(state,response);state.iterations++;
    String text=text(response.output());
    boolean refusal=response.output().findValues("type").stream().anyMatch(v->"refusal".equals(v.asText()));
    if("incomplete".equals(response.status())) {
     state.pendingAnswer=(text.isBlank()?"The provider could not complete this response.":text)+"\n\nResponse incomplete; no enforcement action was taken.";
     db.audit(turn.owner(),turn.session(),turn.id(),"INCOMPLETE",null,turn.model(),turn.effort(),0,0);
    } else if(refusal||pending(state.protocol).isEmpty()) {
     state.pendingAnswer=text.isBlank()?"The provider returned no answer. Try a narrower rule question.":text;
     if(refusal)db.audit(turn.owner(),turn.session(),turn.id(),"REFUSED",null,turn.model(),turn.effort(),0,0);
    }
    db.checkpoint(turn,state,false);
   }
  } catch(AccessDeniedException e){db.terminal(turn,"FAILED","ACCESS_REVOKED");}
  catch(org.springframework.web.server.ResponseStatusException e){if(e.getStatusCode().value()==404)return;db.terminal(turn,"FAILED",e.getStatusCode().value()==410?"CONVERSATION_EXPIRED":"SOURCE_UNAVAILABLE");}
  catch(LlmClient.ProviderFailure e){db.terminal(turn,"FAILED",e.code());}
  catch(InterruptedException e){Thread.currentThread().interrupt();}
  catch(IOException e){db.audit(turn.owner(),turn.session(),turn.id(),"STORAGE_RECOVERY_REQUIRED",null,turn.model(),turn.effort(),0,0);}
  catch(IllegalStateException e){String code=e.getMessage();if("LEASE_LOST".equals(code))return;db.terminal(turn,"FAILED",Set.of("TURN_DEADLINE","TURN_BUDGET","SHARED_BUDGET","FEATURE_BUDGET","PROVIDER_USAGE_EXCEEDS_RESERVATION","RECOVERY_CONFIGURATION","MODEL_UNAVAILABLE").contains(code)?code:"PROTOCOL_LIMIT");}
  catch(RuntimeException e){db.terminal(turn,"FAILED","ASSISTANT_FAILED");}
 }
 private void completeLimit(AssistantPersistence.Turn t,AssistantState s,String message)throws IOException{finish(t,s,message);db.audit(t.owner(),t.session(),t.id(),"LIMIT_REACHED",null,t.model(),t.effort(),0,0);}
 public static List<JsonNode> pending(ArrayNode protocol){Set<String> results=new HashSet<>();protocol.forEach(item->{if("function_call_output".equals(item.path("type").asText()))results.add(item.path("call_id").asText());});List<JsonNode> calls=new ArrayList<>();protocol.forEach(item->{if("function_call".equals(item.path("type").asText())&&!results.contains(item.path("call_id").asText()))calls.add(item);});return calls;}
 private static void append(AssistantState s,LlmClient.Response response){
  Set<String> ids=new HashSet<>();for(var item:s.protocol)if("function_call".equals(item.path("type").asText()))ids.add(item.path("call_id").asText());
  for(var item:response.output()){
   String type=item.path("type").asText();if(!Set.of("message","function_call","reasoning").contains(type))throw new IllegalStateException("PROVIDER_PROTOCOL");
   if("function_call".equals(type)){String id=item.path("call_id").asText();if(!id.matches("[A-Za-z0-9_-]{1,128}")||!ids.add(id)||!item.path("name").isTextual()||!item.path("arguments").isTextual())throw new IllegalStateException("PROVIDER_PROTOCOL");}
   s.protocol.add(AssistantToolRegistry.redact(item));
  }
 }
 public static String text(ArrayNode output){StringBuilder text=new StringBuilder();for(var item:output)if("message".equals(item.path("type").asText()))for(var content:item.path("content")){String type=content.path("type").asText();if("output_text".equals(type))text.append(content.path("text").asText()).append('\n');else if("refusal".equals(type))text.append(content.path("refusal").asText()).append('\n');}return AssistantText.redact(text.toString().trim());}
}
