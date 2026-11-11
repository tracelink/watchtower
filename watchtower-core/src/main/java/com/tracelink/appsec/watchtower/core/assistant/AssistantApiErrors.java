package com.tracelink.appsec.watchtower.core.assistant;

import java.util.Map;
import java.io.IOException;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;

@RestControllerAdvice(basePackages={"com.tracelink.appsec.watchtower.core.assistant","com.tracelink.appsec.watchtower.core.feedback","com.tracelink.appsec.watchtower.core.rule.report","com.tracelink.appsec.watchtower.core.rule.variant","com.tracelink.appsec.watchtower.core.rule.upstream"},assignableTypes={com.tracelink.appsec.watchtower.core.rule.RuleEvidenceController.class})
public class AssistantApiErrors {
 /** A shared draft that is refused says why, in its own words; every other bad request stays generic. */
 @ExceptionHandler(com.tracelink.appsec.watchtower.core.assistant.context.DraftShare.Refused.class) public ResponseEntity<Object> draftRefused(com.tracelink.appsec.watchtower.core.assistant.context.DraftShare.Refused e){return ResponseEntity.badRequest().body(Map.of("error",e.getMessage()));}
 @ExceptionHandler(IllegalArgumentException.class) public ResponseEntity<Object> invalid(){return ResponseEntity.badRequest().body(Map.of("error","Invalid request; check fields, scope and limits."));}
 @ExceptionHandler(org.springframework.dao.OptimisticLockingFailureException.class) public ResponseEntity<Object> conflict(){return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error","Changed by someone else; reload and try again."));}
 @ExceptionHandler(IOException.class) public ResponseEntity<Object> storage(){return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("error","Provider or transcript storage unavailable; retry later."));}
 @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class) public ResponseEntity<Object> status(org.springframework.web.server.ResponseStatusException e){var response=ResponseEntity.status(e.getStatusCode());if(e.getStatusCode().value()==429)response.header("Retry-After","30");return response.body(Map.of("error",e.getReason()==null?"Request unavailable":e.getReason()));}
}
