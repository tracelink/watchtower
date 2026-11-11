package com.tracelink.appsec.watchtower.core.rule.report;

import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** Viewing needs Ruleset View; running and scheduling need Rule Modify (CSRF applies to POSTs). */
@RestController
@RequestMapping("/rule/review-report")
public class RuleReviewReportController {
 public record Settings(Boolean enabled,Integer weekday,Long version) { }
 private final RuleReviewReportService reports;private final ThemeNamingService naming;
 public RuleReviewReportController(RuleReviewReportService reports,ThemeNamingService naming){this.reports=reports;this.naming=naming;}
 @GetMapping @PreAuthorize("hasAuthority('Ruleset View')")
 public Map<String,Object> latest(){return naming.attach(reports.latest());}
 @PostMapping("/run") @PreAuthorize("hasAuthority('Rule Modify')")
 public Map<String,Object> run(Authentication auth){reports.runNow(auth.getName());return latest();}
 @PostMapping("/settings") @PreAuthorize("hasAuthority('Rule Modify')")
 public Map<String,Object> settings(@RequestBody Settings settings,Authentication auth){
  if(settings==null||settings.enabled()==null||settings.weekday()==null||settings.version()==null)throw new IllegalArgumentException("enabled, weekday and version are required");
  reports.change(settings.enabled(),settings.weekday(),settings.version(),auth.getName());return latest();
 }
}
