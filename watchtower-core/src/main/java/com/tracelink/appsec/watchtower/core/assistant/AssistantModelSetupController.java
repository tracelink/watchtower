package com.tracelink.appsec.watchtower.core.assistant;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;

@RestController @RequestMapping("/admin/assistant/models") @PreAuthorize("hasAuthority('Assistant Admin')")
public class AssistantModelSetupController {
 private final AssistantModelSetup setup;
 public AssistantModelSetupController(AssistantModelSetup setup){this.setup=setup;}
 @PostMapping("/approve") public Object approve(@RequestBody AssistantModelSetup.Configure request,Authentication a){return setup.configure(request,a.getName());}
 @ExceptionHandler(IllegalArgumentException.class) public org.springframework.http.ResponseEntity<?> invalid(IllegalArgumentException e){return org.springframework.http.ResponseEntity.badRequest().body(java.util.Map.of("error",e.getMessage()));}
}

