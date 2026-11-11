package com.tracelink.appsec.watchtower.core.assistant.features;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** The AI helpers that sit beside existing pages. Each returns a suggestion; none of them changes anything. */
@RestController
@RequestMapping("/assistant")
@PreAuthorize("hasAuthority('Assistant Use')")
public class FeatureController {
 private final BypassSummaryService bypassSummaries;private final JobDiagnosisService diagnoses;private final HelperAvailability helpers;private final OnboardingService onboarding;private final FixtureDraftService fixtures;private final AlertCopilotService alertCopilot;
 public FeatureController(BypassSummaryService bypassSummaries,JobDiagnosisService diagnoses,HelperAvailability helpers,OnboardingService onboarding,FixtureDraftService fixtures,AlertCopilotService alertCopilot){this.bypassSummaries=bypassSummaries;this.diagnoses=diagnoses;this.helpers=helpers;this.onboarding=onboarding;this.fixtures=fixtures;this.alertCopilot=alertCopilot;}
 public record AlertCopilotRequest(String text) { }
 /** Which helpers to show this person; cheap, and never asks the model. */
 @GetMapping("/helpers") public Map<String,Boolean> helpers(Authentication a){return helpers.of(a.getName());}
 @PostMapping("/bypass-summary/{requestId}") public Map<String,Object> bypassSummary(@PathVariable long requestId,Authentication a){return bypassSummaries.summarize(a.getName(),requestId);}
 @PostMapping("/diagnose-job/{jobId}") public Map<String,Object> diagnoseJob(@PathVariable long jobId,Authentication a){return diagnoses.diagnose(a.getName(),jobId);}
 @PostMapping("/onboarding/{repositoryId}") public Map<String,Object> suggestRuleset(@PathVariable long repositoryId,Authentication a){return onboarding.suggest(a.getName(),repositoryId);}
 @PostMapping("/draft-fixture/{caseId}") public Map<String,Object> draftFixture(@PathVariable String caseId,Authentication a){return fixtures.draft(a.getName(),caseId);}
 @PostMapping("/alert-copilot") public Map<String,Object> alertCopilot(@RequestBody AlertCopilotRequest body,Authentication a){return alertCopilot.draft(a.getName(),body==null?null:body.text());}
 @ExceptionHandler(IllegalArgumentException.class) public ResponseEntity<Object> invalid(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("error",e.getMessage()));}
}
