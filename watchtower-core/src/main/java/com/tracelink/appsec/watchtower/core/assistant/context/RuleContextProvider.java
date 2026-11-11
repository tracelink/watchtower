package com.tracelink.appsec.watchtower.core.assistant.context;

import java.util.*;
import org.springframework.stereotype.Component;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/** The card for a rule page: name, engine, state and revision; a rule's definition comes from the rule tools. */
@Component
public class RuleContextProvider implements ContextProvider {
 private final RuleService rules;
 public RuleContextProvider(RuleService rules){this.rules=rules;}
 @Override public String kind(){return "rule";}
 @Override public Set<String> grants(){return Set.of("Ruleset View");}
 @Override public ContextCard resolve(ContextRequest.Ids ids){
  if(ids.ruleId()==null||ids.ruleId()<1)return ContextCard.unavailable(kind());
  RuleDto rule;
  try{rule=rules.getRule(ids.ruleId()).toDto();}catch(Exception e){return ContextCard.unavailable(kind());}
  var facts=new LinkedHashMap<String,Object>();
  facts.put("name",rule.getName());facts.put("engine",rule.getModule());facts.put("revision",rule.getRevision());
  if(rule.getStewardship()!=null){facts.put("state",String.valueOf(rule.getStewardship().getState()));if(rule.getStewardship().getOwner()!=null)facts.put("owner",rule.getStewardship().getOwner());}
  return ContextCard.ok(kind(),"Rule · "+rule.getName(),facts,ContextService.idMap(new ContextRequest.Ids(null,null,null,null,rule.getId())));
 }
}
