package com.tracelink.appsec.watchtower.core.assistant.alerts;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** Reads, applies, cancels and refreshes drafted alert-route changes. Applying needs the person's own grants. */
@RestController
@RequestMapping("/assistant/alert-changes")
@PreAuthorize("hasAuthority('Assistant Use')")
public class AlertRouteChangeSetController {
 private final AlertRouteChangeSetService changes;
 public AlertRouteChangeSetController(AlertRouteChangeSetService changes){this.changes=changes;}
 @GetMapping("/{id}") public Object get(@PathVariable String id,Authentication a){return changes.get(id,a.getName());}
 @PostMapping("/{id}/apply") public Object apply(@PathVariable String id,@RequestBody AlertRouteActions.Approval approval,Authentication a){return changes.apply(id,approval,a.getName());}
 @PostMapping("/{id}/cancel") public Object cancel(@PathVariable String id,Authentication a){return changes.cancel(id,a.getName());}
 @PostMapping("/{id}/refresh") public Object refresh(@PathVariable String id,Authentication a){return changes.refresh(id,a.getName());}
 @ExceptionHandler(IllegalArgumentException.class) public ResponseEntity<?> invalid(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("code","INVALID_INPUT","error",e.getMessage()));}
 @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class) public ResponseEntity<?> status(org.springframework.web.server.ResponseStatusException e){
  int code=e.getStatusCode().value();
  String reason=e.getReason()==null?"Change set unavailable":e.getReason();
  return ResponseEntity.status(e.getStatusCode()).body(Map.of("code",code==410?"APPROVAL_EXPIRED":code==409?conflictCode(reason):"UNAVAILABLE","error",reason));
 }
 /** Tells the page why a request was refused: routes changed (look again), or the draft itself is not applicable. */
 public static String conflictCode(String reason){
  if(AlertRouteChangeSetService.CHANGED.equals(reason)||reason.contains("was edited or removed"))return "STALE_STATE";
  if(reason.contains("canceled"))return "CANCELED";
  if(reason.contains("pending"))return "NOT_PENDING";
  return "CONFLICT";
 }
 @ExceptionHandler(org.springframework.dao.OptimisticLockingFailureException.class) public ResponseEntity<?> stale(){
  return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("code","STALE_STATE","error",AlertRouteChangeSetService.CHANGED));
 }
}
