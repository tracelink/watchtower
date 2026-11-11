package com.tracelink.appsec.watchtower.core.assistant.batch;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** Start a batch triage of a scan, and read how it is going. It only gathers advice; nothing is judged. */
@RestController
@RequestMapping("/assistant/batch-triage")
@PreAuthorize("hasAuthority('Assistant Use')")
public class BatchTriageController {
 public record Start(String scanType,Long scanId) { }
 private final BatchTriageService triage;
 public BatchTriageController(BatchTriageService triage){this.triage=triage;}
 @PostMapping public ResponseEntity<Map<String,Object>> start(@RequestBody Start request,Authentication a){
  if(request==null||request.scanId()==null)throw new IllegalArgumentException("scanType and scanId are required");
  return ResponseEntity.accepted().body(triage.start(a.getName(),request.scanType(),request.scanId()));
 }
 @GetMapping("/{scanType}/{scanId}") public Map<String,Object> view(@PathVariable String scanType,@PathVariable long scanId,Authentication a){return triage.view(a.getName(),scanType,scanId);}
 @ExceptionHandler(IllegalArgumentException.class) public ResponseEntity<Object> invalid(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("error",e.getMessage()));}
}
