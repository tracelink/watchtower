package com.tracelink.appsec.watchtower.core.assistant;

import java.io.IOException;
import java.util.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.http.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/assistant")
@PreAuthorize("hasAuthority('Assistant Use')")
public class AssistantController {
 private final AssistantPersistence db;private final AssistantSettingsService settings;private final AssistantAccess access;private final AssistantToolRegistry tools;private final AssistantStreams streams;private final AssistantBudgetService budgets;
 public AssistantController(AssistantPersistence db,AssistantSettingsService settings,AssistantAccess access,AssistantToolRegistry tools,AssistantStreams streams,AssistantBudgetService budgets){this.db=db;this.settings=settings;this.access=access;this.tools=tools;this.streams=streams;this.budgets=budgets;}
 private com.tracelink.appsec.watchtower.core.assistant.context.ContextService contexts;
 @org.springframework.beans.factory.annotation.Autowired(required=false) void setContexts(com.tracelink.appsec.watchtower.core.assistant.context.ContextService contexts){this.contexts=contexts;}
 private com.tracelink.appsec.watchtower.core.assistant.context.DraftShare drafts;
 @org.springframework.beans.factory.annotation.Autowired(required=false) void setDrafts(com.tracelink.appsec.watchtower.core.assistant.context.DraftShare drafts){this.drafts=drafts;}
 private AssistantMaintenance maintenance;
 @org.springframework.beans.factory.annotation.Autowired(required=false) void setMaintenance(AssistantMaintenance maintenance){this.maintenance=maintenance;}
 private void check(Authentication a){db.enabled();access.require(a.getName(),"Assistant Use");}
 @PostMapping("/turn") public ResponseEntity<Object> submit(@RequestBody AssistantPersistence.Submit r,Authentication a)throws IOException {
  check(a);
  // Replay prior evidence authorization before it can enter another turn or provider request.
  if(r.sessionId()!=null){var session=db.session(r.sessionId(),a.getName());if(session.get("latest_key")!=null){var state=AssistantState.decode(db.store().get((String)session.get("latest_key"),1048576),1048576);tools.replay(a.getName(),state);}}
  // A retry of a turn already accepted gets that turn back, so its page card is not rebuilt.
  var card=contexts==null||r.context()==null||db.hasTurn(a.getName(),r.idempotencyKey())?null:contexts.forSubmit(a.getName(),r.context());
  // A shared draft is checked and redacted here, before anything is stored. A retry is checked the same way, so it matches the turn it repeats.
  String draft=r.draft()==null||r.draft().isBlank()||drafts==null?null:drafts.accept(r.draft());
  var t=db.submit(r,a.getName(),card,draft);return ResponseEntity.accepted().body(Map.of("turnId",t.id(),"sessionId",t.session(),"status",t.status(),"context",card==null?"NONE":card.state()));
 }
 /** Polling fallback for the progress stream; both views share authorization and rendering. */
 @GetMapping("/turn/{id}") public Object turn(@PathVariable String id,Authentication a)throws IOException{return streams.view(id,a.getName());}
 @GetMapping(path="/turn/{id}/events",produces=MediaType.TEXT_EVENT_STREAM_VALUE) public SseEmitter events(@PathVariable String id,Authentication a,HttpServletResponse response)throws IOException{
  // Reverse proxies must not buffer progress events.
  response.setHeader("X-Accel-Buffering","no");response.setHeader(HttpHeaders.CACHE_CONTROL,"no-store");return streams.open(id,a.getName());}
 @PostMapping("/turn/{id}/cancel") public Object cancel(@PathVariable String id,Authentication a){check(a);db.cancel(id,a.getName());return Map.of("status","CANCELED");}
 @GetMapping("/history") public Object history(@RequestParam(defaultValue="0")int offset,Authentication a){check(a);return db.history(a.getName(),offset);}
 @GetMapping("/active") public Object active(Authentication a){check(a);return db.records().maps("SELECT turnId AS turn_id,sessionId AS session_id FROM AssistantTurnEntity WHERE activeUser=?1",0,1 ,AssistantPersistence.ownerKey(a.getName()));}
 /** One storage read serves both the grant re-check and the messages shown, so reopening a chat is as fast as one fetch. */
 @GetMapping("/history/{id}") public Object conversation(@PathVariable String id,Authentication a)throws IOException{check(a);var session=db.session(id,a.getName());List<Map<String,Object>> messages=List.of();if(session.get("latest_key")!=null){var state=AssistantState.decode(db.store().get((String)session.get("latest_key"),1048576),1048576);tools.replay(a.getName(),state);messages=AssistantPersistence.messages(state);}return Map.of("session",session,"messages",messages,"turns",db.records().maps("SELECT turnId AS turn_id,status AS status,createdAt AS created_at,errorCode AS error_code FROM AssistantTurnEntity WHERE sessionId=?1 ORDER BY createdAt,turnId",0,100 ,AssistantPersistence.uuid(id)));}
 /** A person deletes one of their own chats; stored copies go now where possible, otherwise the daily job finishes it. */
 @DeleteMapping("/history/{id}") public Object delete(@PathVariable String id,Authentication a){check(a);db.delete(id,a.getName());if(maintenance!=null)maintenance.purgeSession(AssistantPersistence.uuid(id));return Map.of("status","DELETED");}
 /** Always reachable for Assistant Use, even when chat is off, so the drawer can say what is missing. */
 @GetMapping("/status") public Object status(Authentication a){access.require(a.getName(),"Assistant Use");return settings.readiness();}
 @GetMapping("/models") public Object models(Authentication a){check(a);var cfg=settings.get().settings();return Map.of("models",cfg.allowedModels().stream().map(m->Map.of("id",m.id(),"efforts",m.efforts())).toList(),"defaultModel",cfg.defaultModel(),"defaultEffort",cfg.defaultEffort(),"retentionDays",cfg.retentionDays(),"rulesetActions",cfg.rulesetActionsEnabled(),"contextCards",cfg.isFeatureOn(AssistantFeature.CONTEXT_CARDS));}
 /** How the server understands the page the drawer is on, for the context chip; ids only, never page text. */
 @PostMapping("/context") public Object context(@RequestBody com.tracelink.appsec.watchtower.core.assistant.context.ContextRequest request,Authentication a){
  check(a);return contexts==null?new com.tracelink.appsec.watchtower.core.assistant.context.ContextService.Preview("NONE",null,null,List.of()):contexts.preview(a.getName(),request);
 }
 /** The caller's own spend today against their daily cost cap, for the drawer's budget chip. */
 @GetMapping("/budget") public Object budget(Authentication a){check(a);var cfg=settings.get().settings();var today=budgets.today(a.getName());
  // Where the organization's day went: each AI feature that has a share, so a full share is explained.
  var features=new ArrayList<Map<String,Object>>();
  for(var feature:AssistantFeature.values()){
   var slice=cfg.featureSlice(feature);boolean active=feature==AssistantFeature.FINDING_ASSESSMENT?cfg.findingAssessment().enabled():cfg.isFeatureOn(feature);
   if(active&&slice.isPresent())features.add(Map.of("name",feature.label(),"usedCostMicros",budgets.usedToday(feature).get("cost_micros"),"dailyCostMicros",slice.get().dailyCostMicros()));
  }
  return Map.of("usedCostMicros",budgets.usedTodayMicros(a.getName()),"dailyCostMicros",cfg.userDailyCostMicros(),"orgUsedCostMicros",today.get("org_cost_micros"),"orgDailyCostMicros",cfg.orgDailyCostMicros(),"features",features);}
 public record Outcome(Integer rating,String taskType,Long elapsedSeconds,Long savedSeconds) { }
 @PostMapping("/turn/{id}/outcome") public Object outcome(@PathVariable String id,@RequestBody Outcome o,Authentication a){check(a);var t=db.turn(id);db.own(t,a.getName());if(!"COMPLETED".equals(t.status())||o.rating()!=null&&(o.rating()<1||o.rating()>5)||o.taskType()!=null&&!Set.of("UNDERSTAND_RULE","RESOLVE_FINDING","REVIEW_CHANGE").contains(o.taskType())||o.elapsedSeconds()!=null&&(o.elapsedSeconds()<0||o.elapsedSeconds()>86400)||o.savedSeconds()!=null&&(o.savedSeconds()<0||o.savedSeconds()>86400))throw new IllegalArgumentException("Invalid outcome");
  db.transaction().executeWithoutResult(tx->{
   db.records().lock(com.tracelink.appsec.watchtower.core.persistence.AssistantTurnEntity.class,t.id());
   db.records().save(new com.tracelink.appsec.watchtower.core.persistence.AssistantOutcomeEntity(t.id(),a.getName(),o.rating(),o.taskType(),o.elapsedSeconds(),o.savedSeconds(),System.currentTimeMillis()));
   db.audit(a.getName(),t.session(),t.id(),"OUTCOME_RECORDED",o.taskType(),t.model(),t.effort(),0,0);});return Map.of("status","saved");}
}
