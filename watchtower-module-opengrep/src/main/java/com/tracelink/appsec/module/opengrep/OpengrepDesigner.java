package com.tracelink.appsec.module.opengrep;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.module.designer.*;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

@Component
public class OpengrepDesigner implements IRuleDesigner {
 private static final int MAX_RULE_ID = 80;
 private static final ObjectMapper JSON = new ObjectMapper();
 public String getPrivilegeNameForAccess(){return OpengrepModule.DESIGN;}
 public RuleDesignerModelAndView getDefaultRuleDesignerModelAndView(){return new RuleDesignerModelAndView("designer/opengrep");}

 /**
  * The designer with a drafted rule's fields filled in. Opengrep has no test run in the designer, so the drafted
  * examples are shown above the page for the person to try in Test improvements once the rule is saved.
  */
 @Override public RuleDesignerModelAndView getPrefilledRuleDesignerModelAndView(RuleDraftData draft){
  RuleDesignerModelAndView mav=getDefaultRuleDesignerModelAndView();
  Map<String,String> rule=new LinkedHashMap<>();
  rule.put("name",draft.name());
  rule.put("priority",RulePriority.valueOf(draft.priority()).name());
  rule.put("engineRuleId",ruleId(draft.name()));
  rule.put("message",draft.message());
  rule.put("externalUrl",draft.cwe()==null?"":"https://cwe.mitre.org/data/definitions/"+draft.cwe().substring("CWE-".length())+".html");
  rule.put("definition",draft.definition());
  mav.addObject("draftRule",rule);
  return mav;
 }

 /** The rule definition must be one JSON object, as the designer form expects. */
 @Override public String validateDraft(RuleDraftData draft){
  try{return JSON.readTree(draft.definition()).isObject()?null:"An Opengrep rule definition must be one JSON object.";}
  catch(com.fasterxml.jackson.core.JsonProcessingException e){return "An Opengrep rule definition must be valid JSON.";}
 }

 /** A stable id from the name: lower case words joined by dashes. */
 static String ruleId(String name){
  String slug=name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+","-").replaceAll("^-+|-+$","");
  slug=slug.isEmpty()?"drafted-rule":slug;
  return "wt-"+(slug.length()>MAX_RULE_ID?slug.substring(0,MAX_RULE_ID):slug);
 }
}
