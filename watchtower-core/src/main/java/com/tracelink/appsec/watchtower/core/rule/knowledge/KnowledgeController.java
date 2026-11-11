package com.tracelink.appsec.watchtower.core.rule.knowledge;

import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** Viewing needs Ruleset View; proposing and deciding need Rule Modify (CSRF applies to POSTs). */
@RestController
@RequestMapping("/rule/knowledge")
public class KnowledgeController {
 public record Decision(Long version,String note) { }
 private final KnowledgeService knowledge;
 public KnowledgeController(KnowledgeService knowledge){this.knowledge=knowledge;}
 @GetMapping @PreAuthorize("hasAuthority('Ruleset View')")
 public List<Map<String,Object>> list(@RequestParam(defaultValue="APPROVED") String status,@RequestParam(defaultValue="0") int offset,Authentication auth){
  return knowledge.list(status,offset,auth.getName());
 }
 @GetMapping("/{id}/audit") @PreAuthorize("hasAuthority('Ruleset View')")
 public List<Map<String,Object>> audit(@PathVariable String id){return knowledge.audit(id);}
 @PostMapping @PreAuthorize("hasAuthority('Rule Modify')")
 public Map<String,Object> propose(@RequestBody KnowledgeService.Proposal proposal,Authentication auth){return Map.of("id",knowledge.propose(proposal,auth.getName()));}
 @PostMapping("/{id}/approve") @PreAuthorize("hasAuthority('Rule Modify')")
 public Map<String,Object> approve(@PathVariable String id,@RequestBody Decision d,Authentication auth){knowledge.approve(id,version(d),auth.getName());return Map.of("status",KnowledgeService.APPROVED);}
 @PostMapping("/{id}/reject") @PreAuthorize("hasAuthority('Rule Modify')")
 public Map<String,Object> reject(@PathVariable String id,@RequestBody Decision d,Authentication auth){knowledge.reject(id,version(d),d.note(),auth.getName());return Map.of("status",KnowledgeService.REJECTED);}
 @PostMapping("/{id}/retire") @PreAuthorize("hasAuthority('Rule Modify')")
 public Map<String,Object> retire(@PathVariable String id,@RequestBody Decision d,Authentication auth){knowledge.retire(id,version(d),d.note(),auth.getName());return Map.of("status",KnowledgeService.RETIRED);}
 private static long version(Decision d){if(d==null||d.version()==null)throw new IllegalArgumentException("version is required");return d.version();}
 /** Validation messages are written for people and contain no stored data. */
 @ExceptionHandler(IllegalArgumentException.class)
 public ResponseEntity<Object> invalid(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("error",e.getMessage()));}
}
