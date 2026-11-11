package com.tracelink.appsec.watchtower.core.rule.report;

import java.util.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.http.ResponseEntity;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@Controller @RequestMapping("/rules/review-reports") @PreAuthorize("hasAuthority('Ruleset View')")
public class RuleReviewReportPageController {
 private final RuleReviewReportService reports;private final ThemeNamingService naming;
 public RuleReviewReportPageController(RuleReviewReportService reports,ThemeNamingService naming){this.reports=reports;this.naming=naming;}
 @GetMapping
 @SuppressWarnings("unchecked")
 public WatchtowerModelAndView page(@RequestParam(required=false)String reportId,@RequestParam(defaultValue="summary")String view,
   @RequestParam(defaultValue="")String search,@RequestParam(defaultValue="all")String reason,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="25")int pageSize){
  if(!Set.of("summary","attention","themes","coverage","settings").contains(view))throw new IllegalArgumentException("Invalid report view");
  // The schedule moved from a Settings tab into a dialog; old links land on the summary.
  if("settings".equals(view))view="summary";
  var data=reportId==null?reports.latest():reports.saved(reportId);data=naming.attach(data);
  var report=(Map<String,Object>)data.get("report");String selected=report==null?null:(String)report.get("id");
  var mav=new WatchtowerModelAndView("rules/review-reports").addScriptReference("/scripts/rule-review-report.js").addScriptReference("/scripts/cwe-coverage.js");
  mav.addObject("reportData",data);mav.addObject("selectedReport",report);mav.addObject("reportHistory",reports.history());mav.addObject("view",view);mav.addObject("search",search);mav.addObject("reason",reason);
  mav.addObject("reasons",RuleReportPresentation.REASONS);mav.addObject("scheduleLabel",RuleReportPresentation.scheduleLabel((Map<String,Object>)data.get("settings")));
  if(selected!=null){mav.addObject("attention",reports.attention(selected,search,reason,page,pageSize));mav.addObject("reasonCounts",reports.reasonCounts(selected));}
  mav.addObject("pageUrl",UriComponentsBuilder.fromPath("/rules/review-reports").queryParam("reportId",selected).queryParam("view","attention").queryParam("search",search).queryParam("reason",reason).queryParam("pageSize",pageSize).build().encode().toUriString());return mav;
 }
 @GetMapping("/{id}/data") @ResponseBody
 public Map<String,Object> data(@PathVariable String id){return naming.attach(reports.saved(id));}
 @ExceptionHandler(IllegalArgumentException.class) @ResponseBody
 public ResponseEntity<?> invalid(){return ResponseEntity.badRequest().body(Map.of("error","Check the saved report, filters and page size."));}
}
