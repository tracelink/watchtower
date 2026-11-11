package com.tracelink.appsec.watchtower.core.assistant.alerts;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/** The page where a person reviews a drafted set of alert-route changes before applying it. */
@Controller
@RequestMapping("/assistant/alert-changes")
@PreAuthorize("hasAuthority('Assistant Use')")
public class AlertRouteChangeSetPageController {
 private final AlertRouteChangeSetService changes;
 public AlertRouteChangeSetPageController(AlertRouteChangeSetService changes){this.changes=changes;}
 /** Opens only for the person who has the draft and still holds the alert grants; anyone else gets a not-found. */
 @GetMapping("/{id}/review")
 public WatchtowerModelAndView review(@PathVariable String id,Authentication a){
  changes.get(id,a.getName());
  var view=new WatchtowerModelAndView("assistant/alert-change-set").addScriptReference("/scripts/alert-change-set.js");
  view.addObject("changeSetId",id);
  return view;
 }
}
