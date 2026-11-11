package com.tracelink.appsec.watchtower.core.rule.variant;

import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** Same grants as recording a missed case; starting a search also needs Rule Modify (CSRF applies). */
@RestController
@RequestMapping("/repository/evidence/variants")
@PreAuthorize("hasAuthority('Assistant Source Read') and hasAuthority('Repository Settings View') and hasAuthority('Scan Results View')")
public class VariantSearchController {
 private final VariantSearchService searches;
 public VariantSearchController(VariantSearchService searches){this.searches=searches;}
 @GetMapping("/repositories")
 public Object repositories(@RequestParam(defaultValue="") String q,Authentication actor){return searches.repositories(q,actor.getName());}
 @PostMapping
 @PreAuthorize("hasAuthority('Rule Modify') and hasAuthority('Assistant Source Read') and hasAuthority('Repository Settings View') and hasAuthority('Scan Results View')")
 public Object start(@RequestBody VariantSearchService.Start start,Authentication actor){return Map.of("id",searches.start(start,actor.getName()));}
 @GetMapping("/{searchId}")
 public Object get(@PathVariable String searchId,Authentication actor){return searches.get(searchId,actor.getName());}
 @GetMapping("/case/{caseId}")
 public Object forCase(@PathVariable String caseId,Authentication actor){return searches.forCase(caseId,actor.getName());}
}
