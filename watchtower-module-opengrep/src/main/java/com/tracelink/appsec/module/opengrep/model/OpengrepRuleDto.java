package com.tracelink.appsec.module.opengrep.model;

import java.util.Set;
import java.util.TreeSet;
import com.tracelink.appsec.watchtower.core.rule.LanguageScopedRule;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory;

public interface OpengrepRuleDto extends LanguageScopedRule {
 String getEngineRuleId();
 String getDefinition();
 String getLicense();
 String getSource();
 /** Languages named by the definition; an unreadable definition reports none rather than guessing. */
 @Override default Set<String> scannedLanguages(){
  if(getDefinition()==null)return Set.of();
  try{Set<String> languages=new TreeSet<>();RuleDefinitionHistory.JSON.readTree(getDefinition()).path("languages").forEach(l->{if(l.isTextual())languages.add(l.asText());});return languages;}
  catch(java.io.IOException e){return Set.of();}
 }
}
