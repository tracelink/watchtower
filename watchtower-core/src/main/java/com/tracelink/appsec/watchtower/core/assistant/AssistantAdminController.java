package com.tracelink.appsec.watchtower.core.assistant;

import java.util.*;
import java.io.IOException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@Controller
@RequestMapping("/admin/assistant")
public class AssistantAdminController {
 public record TranscriptMessage(String role,String text) { }
 public record Transcript(List<TranscriptMessage> messages,long expiresAt) { }
 private final AssistantPersistence db;private final AssistantSettingsService settings;private final AssistantAccess access;private final OpenAiLlmClient client;private final AssistantToolRegistry tools;
 private AssistantBudgetService budgets;
 public AssistantAdminController(AssistantPersistence db,AssistantSettingsService settings,AssistantAccess access,OpenAiLlmClient client,AssistantToolRegistry tools){this.db=db;this.settings=settings;this.access=access;this.client=client;this.tools=tools;}
 @org.springframework.beans.factory.annotation.Autowired(required=false) void setBudgets(AssistantBudgetService budgets){this.budgets=budgets;}
 @GetMapping @PreAuthorize("hasAuthority('Assistant Audit') or hasAuthority('Assistant Admin')") public WatchtowerModelAndView page(){return new WatchtowerModelAndView("assistant/admin").addScriptReference("/scripts/assistant-model-setup.js").addScriptReference("/scripts/assistant-settings-form.js").addScriptReference("/scripts/assistant-admin-layout.js").addScriptReference("/scripts/assistant-admin.js").addScriptReference("/scripts/assistant-evaluation.js").addScriptReference("/scripts/ai-integration.js");}
 @GetMapping("/settings") @ResponseBody @PreAuthorize("hasAuthority('Assistant Admin')") public Object settings(Authentication a){access.require(a.getName(),"Assistant Admin");var view=new LinkedHashMap<String,Object>();view.put("configuration",settings.get());view.put("readiness",settings.readiness());
  // What today's daily budgets have already charged, so a "daily budget reached" stop can be explained.
  if(budgets!=null)view.put("usage_today",budgets.today(a.getName()));return view;}
 @PostMapping("/settings") @ResponseBody @PreAuthorize("hasAuthority('Assistant Admin')") public Object save(@RequestBody AssistantSettingsService.Versioned v,Authentication a){access.require(a.getName(),"Assistant Admin");settings.save(v,a.getName());return Map.of("status","saved");}
 @GetMapping("/models") @ResponseBody @PreAuthorize("hasAuthority('Assistant Admin')") public Object discover(Authentication a)throws IOException,InterruptedException{access.require(a.getName(),"Assistant Admin");return Map.of("accessibleIds",client.discover(),"limitation","Discovery does not certify capabilities or pricing and does not enable any model.");}
 @GetMapping("/audit") @ResponseBody @PreAuthorize("hasAuthority('Assistant Audit')") public Object audit(@RequestParam(defaultValue="0")int offset,Authentication a){access.require(a.getName(),"Assistant Audit");if(offset<0||offset>10000)throw new IllegalArgumentException("Invalid page");var view=new LinkedHashMap<String,Object>();
  view.put("events",db.records().maps("SELECT row FROM AssistantAuditEntity row ORDER BY auditId DESC",offset,20));
  // budget_blocked: turns refused by the daily budget before any model request (0 tokens is then correct).
  view.put("sessions",db.records().maps("SELECT s.sessionId AS session_id,s.owner AS owner,s.startedAt AS started_at,s.expiresAt AS expires_at,s.turnCount AS turn_count,s.transcriptPurgedAt AS transcript_purged_at,(SELECT COALESCE(SUM(t.tokens),0) FROM AssistantTurnEntity t WHERE t.sessionId=s.sessionId) AS tokens,(SELECT COALESCE(SUM(t.costMicros),0) FROM AssistantTurnEntity t WHERE t.sessionId=s.sessionId) AS cost_micros,(SELECT COUNT(t) FROM AssistantTurnEntity t WHERE t.sessionId=s.sessionId AND t.errorCode IN ('SHARED_BUDGET','FEATURE_BUDGET')) AS budget_blocked FROM AssistantSessionEntity s ORDER BY s.lastTurnAt DESC,s.sessionId",offset,20));
  view.put("retention",AssistantRetentionStatus.recent(db,System.currentTimeMillis()));
  return view;}
 /** UAT #19: answer evaluation as a page; the same script and endpoints drive it. */
 @GetMapping("/evaluation") @PreAuthorize("hasAuthority('Assistant Admin')") public WatchtowerModelAndView evaluationPage(){return new WatchtowerModelAndView("assistant/evaluation").addScriptReference("/scripts/assistant-evaluation.js");}
 /** UAT #19: one expiring transcript as a page. Viewing it is audited exactly as the JSON read is. */
 @GetMapping("/transcripts/{id}") @PreAuthorize("hasAuthority('Assistant Audit')") public WatchtowerModelAndView transcriptPage(@PathVariable String id,Authentication a)throws IOException{
  var mav=new WatchtowerModelAndView("assistant/transcript");mav.addObject("sessionId",id);mav.addObject("expired",false);mav.addObject("denied",false);
  try{var data=transcript(id,a);
   mav.addObject("messages",data.messages());mav.addObject("expiresAt",data.expiresAt());}
  catch(org.springframework.web.server.ResponseStatusException e){if(e.getStatusCode().value()!=410)throw e;mav.addObject("expired",true);}
  // Replaying a chat re-checks the grants behind the tools it used; say so instead of a bare 403
  catch(org.springframework.security.access.AccessDeniedException e){mav.addObject("denied",true);}
  return mav;
 }
 @GetMapping("/transcript/{id}") @ResponseBody @PreAuthorize("hasAuthority('Assistant Audit')") public Transcript transcript(@PathVariable String id,Authentication a)throws IOException{
  access.require(a.getName(),"Assistant Audit");var rows=db.records().maps("SELECT row FROM AssistantSessionEntity row WHERE sessionId=?1",0,2147483647 ,AssistantPersistence.uuid(id));if(rows.isEmpty())throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND);var s=rows.getFirst();
  if(((Number)s.get("expires_at")).longValue()<=System.currentTimeMillis()||s.get("transcript_purged_at")!=null)throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.GONE,"Transcript expired; structured audit remains");
  db.audit(a.getName(),id,null,"AUDIT_TRANSCRIPT_VIEW",null,null,null,0,0);var state=AssistantState.decode(db.store().get((String)s.get("latest_key"),1048576),1048576);
  tools.auditReplay(a.getName(),state);
  // An audit grant permits transcript review, not tool invocation or automatic source retrieval.
  var messages=new ArrayList<TranscriptMessage>();state.messages.forEach(m->messages.add(new TranscriptMessage(m.path("role").asText(""),m.path("text").asText(""))));
  return new Transcript(List.copyOf(messages),((Number)s.get("expires_at")).longValue());
 }
 @GetMapping("/outcomes") @ResponseBody @PreAuthorize("hasAuthority('Assistant Audit')") public Object outcomes(Authentication a){access.require(a.getName(),"Assistant Audit");return db.records().maps("SELECT taskType AS task_type,COUNT(*) responses,AVG(rating) average_rating,AVG(elapsedSeconds) average_elapsed_seconds,AVG(savedSeconds) reported_saved_seconds FROM AssistantOutcomeEntity GROUP BY taskType",0,2147483647);}
}
