package com.tracelink.appsec.watchtower.core.rule.upstream;

import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** Viewing upstream updates needs Ruleset View; releasing held rules needs Rule Modify (CSRF applies). */
@RestController
@RequestMapping("/rule/upstream-updates")
public class UpstreamUpdateController {
 public record Approve(Long version) { }
 private final UpstreamSyncService sync;
 public UpstreamUpdateController(UpstreamSyncService sync){this.sync=sync;}
 @GetMapping @PreAuthorize("hasAuthority('Ruleset View')")
 public Object list(){return sync.list();}
 @PostMapping("/{updateId}/approve") @PreAuthorize("hasAuthority('Rule Modify')")
 public Object approve(@PathVariable String updateId,@RequestBody Approve body,Authentication auth){
  if(body==null||body.version()==null)throw new IllegalArgumentException("version is required");
  sync.approve(updateId,body.version(),auth.getName());return Map.of("updates",sync.list());
 }
}
