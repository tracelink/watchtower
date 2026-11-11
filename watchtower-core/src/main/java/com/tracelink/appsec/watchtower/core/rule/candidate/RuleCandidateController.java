package com.tracelink.appsec.watchtower.core.rule.candidate;

import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import com.tracelink.appsec.watchtower.core.job.*;

@RestController
@RequestMapping("/rule/candidates")
@PreAuthorize("hasAuthority('Rule Modify')")
public class RuleCandidateController {
 private final RuleCandidateService candidates;private final AsyncJobService jobs;private final RuleShadowService shadow;
 private final com.tracelink.appsec.watchtower.core.assistant.AssistantAccess access;
 public RuleCandidateController(RuleCandidateService candidates,AsyncJobService jobs,RuleShadowService shadow,
   com.tracelink.appsec.watchtower.core.assistant.AssistantAccess access){this.candidates=candidates;this.jobs=jobs;this.shadow=shadow;this.access=access;}
 @GetMapping("/workspace/{id}") public RuleCandidateWorkspace workspace(@PathVariable long id){return candidates.workspace(id);}
 @GetMapping("/rule/{id}") public Object list(@PathVariable long id,@RequestParam(defaultValue="0")int offset){return candidates.list(id,offset);}
 @GetMapping("/rule/{id}/page") public Object page(@PathVariable long id,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="25")int pageSize){return candidates.page(id,page,pageSize);}
 @GetMapping("/rule/{id}/preparation") public RuleCandidateService.Preparation preparation(@PathVariable long id){return candidates.preparation(id);}
 @PostMapping("/fixtures/from-case") public Object registerCase(@RequestBody RuleCandidateService.CaseFixture request,Authentication a){return Map.of("id",candidates.registerCase(request,a.getName()));}
 @GetMapping("/{id}") public Object candidate(@PathVariable String id){return candidates.candidate(id);}
 @GetMapping("/{id}/runs") public Object runs(@PathVariable String id){return candidates.runs(id);}
 @GetMapping("/{id}/audit") public Object audit(@PathVariable String id){return candidates.audit(id);}
 @GetMapping("/{id}/shadow") @PreAuthorize("hasAuthority('Rule Modify') and hasAuthority('Scan Results View')")
 public Object shadow(@PathVariable String id,@RequestParam(defaultValue="30")int days){candidates.candidate(id);return shadow.observations(id,days);}
 @PostMapping public Object create(@RequestBody RuleCandidateWorkspace.DraftRequest d,Authentication a){return Map.of("id",candidates.create(d,a.getName()));}
 @PostMapping("/fixtures") public Object fixture(@RequestBody RuleCandidateService.Fixture f,Authentication a){return Map.of("id",candidates.fixture(f,a.getName()));}
 @PostMapping("/{id}/test") public Object test(@PathVariable String id,Authentication a){
  String run=candidates.prepareRun(id,a.getName());
  try {
   var job=jobs.enqueue(AsyncJobType.RULE_CANDIDATE_TEST,run,"candidate-test-"+id,a.getName());
   if(job.isEmpty()){candidates.failRun(run);throw new IllegalStateException("The test queue is unavailable");}
   return Map.of("runId",run,"jobId",job.get().getId());
  }catch(RuntimeException e){candidates.failRun(run);throw e;}
 }
 @PostMapping("/{id}/{action}") public Object action(@PathVariable String id,@PathVariable String action,
   @RequestBody RuleCandidateService.Action approval,Authentication a){
  if(action.equalsIgnoreCase("shadow"))for(String grant:java.util.List.of("Assistant Source Read","Scan Results View"))access.require(a.getName(),grant);
  candidates.transition(id,action.toUpperCase(java.util.Locale.ROOT),approval,a.getName());return Map.of("saved",true);
 }
 @ExceptionHandler(IllegalArgumentException.class) public ResponseEntity<Object> invalid(IllegalArgumentException e){
  // These services throw fixed sentences naming what is wrong, never text from the request; say which one
  return ResponseEntity.badRequest().body(Map.of("error",reasonFor(e)));
 }
 static String reasonFor(IllegalArgumentException e){
  String why=e.getMessage();
  return why==null||why.isBlank()||why.length()>200?"Check the exact rule revision, authored fields and reviewed fixture references.":why+".";
 }
 @ExceptionHandler({IllegalStateException.class,org.springframework.dao.DataIntegrityViolationException.class})
 public ResponseEntity<Object> unavailable(){return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error","Test service or reviewed evidence unavailable, or another action is in progress. Reload and retry."));}
 @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class)
 public ResponseEntity<Object> status(org.springframework.web.server.ResponseStatusException e){return ResponseEntity.status(e.getStatusCode()).body(Map.of("error",e.getReason()));}
}
