package com.tracelink.appsec.watchtower.core.assistant.actions;

import java.util.Map;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.http.*;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@Controller
@RequestMapping("/assistant/change-sets")
@PreAuthorize("hasAuthority('Assistant Use')")
public class RulesetChangeSetController {
 private final RulesetChangeSetService actions;
 public RulesetChangeSetController(RulesetChangeSetService actions){this.actions=actions;}
 @PostMapping @ResponseBody public Object prepare(@RequestBody RulesetActions.Request r,Authentication a){return actions.prepare(r,a.getName(),null);}
 @GetMapping("/{id}") @ResponseBody public Object get(@PathVariable String id,Authentication a){return actions.get(id,a.getName());}
 @GetMapping("/{id}/review") public WatchtowerModelAndView review(@PathVariable String id,Authentication a){actions.get(id,a.getName());var view=new WatchtowerModelAndView("assistant/change-set").addScriptReference("/scripts/ruleset-change-set.js");view.addObject("changeSetId",id);return view;}
 @PostMapping("/{id}/apply") @ResponseBody public Object apply(@PathVariable String id,@RequestBody RulesetActions.Approval approval,Authentication a){return actions.apply(id,approval,a.getName());}
 @PostMapping("/{id}/cancel") @ResponseBody public Object cancel(@PathVariable String id,Authentication a){return actions.cancel(id,a.getName());}
 @PostMapping("/{id}/refresh") @ResponseBody public Object refresh(@PathVariable String id,Authentication a){return actions.refresh(id,a.getName());}
 @ExceptionHandler(IllegalArgumentException.class) @ResponseBody public ResponseEntity<?> invalid(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("code","INVALID_INPUT","error",e.getMessage()));}
 @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class) @ResponseBody public ResponseEntity<?> status(org.springframework.web.server.ResponseStatusException e){return ResponseEntity.status(e.getStatusCode()).body(Map.of("code",e.getStatusCode().value()==410?"APPROVAL_EXPIRED":e.getStatusCode().value()==409?"STALE_STATE":"UNAVAILABLE","error",e.getReason()==null?"Change set unavailable":e.getReason()));}
 @ExceptionHandler(org.springframework.dao.OptimisticLockingFailureException.class) @ResponseBody public ResponseEntity<?> stale(){return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("code","STALE_STATE","error","Configuration changed. Refresh the preview before approving."));}
}
