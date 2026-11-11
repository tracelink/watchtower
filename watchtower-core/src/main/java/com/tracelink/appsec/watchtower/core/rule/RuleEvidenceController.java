package com.tracelink.appsec.watchtower.core.rule;

import java.util.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;

@RestController
@RequestMapping("/rule/evidence")
@PreAuthorize("hasAuthority('Rule Modify') or hasAuthority('Ruleset View')")
public class RuleEvidenceController {
 private final RuleReviewService reviews;private final RuleHealthService health;
 public RuleEvidenceController(RuleReviewService reviews,RuleHealthService health){this.reviews=reviews;this.health=health;}
 @GetMapping("/{id}/health") @PreAuthorize("hasAuthority('Scan Results View') and (hasAuthority('Rule Modify') or hasAuthority('Ruleset View'))") public Object health(@PathVariable long id,@RequestParam(required=false)String revision,@RequestParam(defaultValue="90")int days,@RequestParam(defaultValue="all")String scanType,@RequestParam(defaultValue="all")String policy){
  var calculated=health.health(id,"unknown".equals(revision)?null:revision==null?reviews.current(id).getRevision():revision,days,scanType,policy);
  // Rule editing draws these plain-word chips by the rule name; the raw chip names stay for other readers.
  var result=new LinkedHashMap<String,Object>(calculated);
  result.put("header_chips",com.tracelink.appsec.watchtower.core.rule.workflow.RuleDetailPresentation.compactHealthChips(calculated,health.minimumSample()));
  return result;}
 @GetMapping("/{id}/revisions") @PreAuthorize("hasAuthority('Scan Results View') and (hasAuthority('Rule Modify') or hasAuthority('Ruleset View'))") public Object revisions(@PathVariable long id){return health.revisions(id);}
 @GetMapping("/{id}/reviews") public Object reviews(@PathVariable long id,@RequestParam(defaultValue="0")int offset){return reviews.list(id,offset);}
 @GetMapping("/reviews/{id}/audit") public Object audit(@PathVariable String id){return reviews.audit(id);}
 @PostMapping("/reviews") @PreAuthorize("hasAuthority('Rule Modify')") public Object save(@RequestBody RuleReviewService.Review r,Authentication a){
  if(r.id()==null&&java.util.Set.of("finding","scan").contains(java.util.Objects.toString(r.evidenceType(),""))&&a.getAuthorities().stream().noneMatch(g->g.getAuthority().equals("Scan Results View")))throw new org.springframework.security.access.AccessDeniedException("Scan evidence requires Scan Results View");
  return Map.of("id",reviews.save(r,a.getName()));}
 @PostMapping("/cases") @PreAuthorize("hasAuthority('Rule Modify')") public Object intake(@RequestBody RuleReviewService.Case c,Authentication a){return Map.of("id",reviews.intake(c,a.getName()));}
 @ExceptionHandler(IllegalArgumentException.class) public org.springframework.http.ResponseEntity<?> invalid(){return org.springframework.http.ResponseEntity.badRequest().body(Map.of("error","Select evidence for this rule revision and check the required fields."));}
}
