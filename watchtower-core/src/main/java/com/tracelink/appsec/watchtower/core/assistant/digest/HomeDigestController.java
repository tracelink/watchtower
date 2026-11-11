package com.tracelink.appsec.watchtower.core.assistant.digest;

import java.util.HashSet;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/** The weekly Home digest. Anyone who can see the dashboard reads it; writing a new one also needs Assistant Use. */
@RestController
@RequestMapping("/home/digest")
public class HomeDigestController {
 private final HomeDigestService digests;
 public HomeDigestController(HomeDigestService digests){this.digests=digests;}
 @GetMapping @PreAuthorize("hasAuthority('Scan Dashboard View')")
 public Map<String,Object> latest(Authentication a){
  var held=new HashSet<String>();for(GrantedAuthority g:a.getAuthorities())held.add(g.getAuthority());
  return digests.latest(held);
 }
 @PostMapping @PreAuthorize("hasAuthority('Scan Dashboard View') and hasAuthority('Assistant Use')")
 public Map<String,Object> refresh(Authentication a){return digests.refresh(a.getName());}
 @ExceptionHandler({IllegalArgumentException.class,IllegalStateException.class})
 public ResponseEntity<Map<String,String>> unavailable(RuntimeException e){
  return ResponseEntity.status(503).body(Map.of("error","The digest could not be written right now."));
 }
 @ExceptionHandler(ResponseStatusException.class)
 public ResponseEntity<Map<String,String>> status(ResponseStatusException e){
  return ResponseEntity.status(e.getStatusCode()).body(Map.of("error",e.getReason()==null?"This is unavailable right now.":e.getReason()));
 }
}
