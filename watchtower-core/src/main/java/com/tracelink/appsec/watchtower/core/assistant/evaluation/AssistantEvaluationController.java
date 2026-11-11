package com.tracelink.appsec.watchtower.core.assistant.evaluation;

import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** Assistant Admin only; starting a run also needs Assistant Use (the questions are asked as you). */
@RestController
@RequestMapping("/admin/assistant/evaluations")
@PreAuthorize("hasAuthority('Assistant Admin')")
public class AssistantEvaluationController {
 public record Start(String model,String effort) { }
 public record Score(Integer score,String note,Long version) { }
 private final AssistantEvaluationService evaluations;
 public AssistantEvaluationController(AssistantEvaluationService evaluations){this.evaluations=evaluations;}
 @GetMapping public Object runs(Authentication actor){return evaluations.runs(actor.getName());}
 @PostMapping public Object start(@RequestBody Start start,Authentication actor){
  return Map.of("id",evaluations.start(start==null?null:start.model(),start==null?null:start.effort(),actor.getName()));
 }
 @GetMapping("/{runId}") public Object get(@PathVariable String runId,Authentication actor){return evaluations.get(runId,actor.getName());}
 @PostMapping("/results/{resultId}/score") public Object score(@PathVariable String resultId,@RequestBody Score score,Authentication actor){
  if(score==null||score.score()==null||score.version()==null)throw new IllegalArgumentException("score and version are required");
  evaluations.score(resultId,score.score(),score.note(),score.version(),actor.getName());return Map.of("status","saved");
 }
}
