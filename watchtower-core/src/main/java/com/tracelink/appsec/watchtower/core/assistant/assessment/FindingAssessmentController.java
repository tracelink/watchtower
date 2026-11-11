package com.tracelink.appsec.watchtower.core.assistant.assessment;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** Requesting and reading assessments needs Assistant Use plus source access (checked in the service); CSRF applies to POST. */
@RestController
public class FindingAssessmentController {
 public record Request(String scanType,Long scanId,String findingKey) { }
 private final FindingAssessmentService assessments;
 public FindingAssessmentController(FindingAssessmentService assessments){this.assessments=assessments;}
 @GetMapping("/finding-assessment") @PreAuthorize("hasAuthority('Assistant Use')")
 public Map<String,Object> latest(@RequestParam String scanType,@RequestParam long scanId,@RequestParam String findingKey,Authentication auth){
  return assessments.latest(auth.getName(),scanType,scanId,findingKey);
 }
 @PostMapping("/finding-assessment") @PreAuthorize("hasAuthority('Assistant Use')")
 public Map<String,Object> assess(@RequestBody Request r,Authentication auth){
  if(r==null||r.scanId()==null)throw new IllegalArgumentException("scanType, scanId and findingKey are required");
  return assessments.assess(auth.getName(),r.scanType(),r.scanId(),r.findingKey());
 }
 @GetMapping("/admin/assistant/assessment-agreement") @PreAuthorize("hasAuthority('Assistant Admin') or hasAuthority('Assistant Audit')")
 public Map<String,Object> agreement(){return assessments.agreement();}
 @ExceptionHandler(IllegalArgumentException.class)
 public ResponseEntity<Object> invalid(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("error",e.getMessage()));}
}
