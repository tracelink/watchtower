package com.tracelink.appsec.module.opengrep;

import java.util.Set;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.module.opengrep.model.OpengrepRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory;

/** Bounded local rule data only. Never a registry URL, config file path, extract rule or autofix. */
public final class OpengrepDefinition {
 private OpengrepDefinition() { }
 public static ObjectNode parse(RuleDto rule){
  var dto=(OpengrepRuleDto)rule;
  if(dto.getEngineRuleId()==null||!dto.getEngineRuleId().matches("[A-Za-z][A-Za-z0-9._-]{0,149}")
    ||dto.getDefinition()==null||dto.getDefinition().length()>60000||dto.getLicense()==null||dto.getLicense().isBlank()
    ||dto.getSource()==null||dto.getSource().isBlank())throw new IllegalArgumentException("Rule ID, licensed source and bounded JSON definition required");
  try {
   JsonNode parsed=RuleDefinitionHistory.JSON.readTree(dto.getDefinition());
   if(!(parsed instanceof ObjectNode node))throw new IllegalArgumentException("Use one rule object");
   var allowed=Set.of("languages","mode","pattern","patterns","pattern-either","pattern-regex","pattern-sources","pattern-sinks","pattern-sanitizers","pattern-propagators","options","paths");
   node.fieldNames().forEachRemaining(key->{if(!allowed.contains(key))throw new IllegalArgumentException("Unsupported rule field");});
   var languages=node.path("languages");
   if(!languages.isArray()||languages.isEmpty()||languages.size()>5)throw new IllegalArgumentException("Languages required");
   for(var language:languages)if(!language.isTextual()||!Set.of("python","javascript","typescript","java","yaml").contains(language.asText()))throw new IllegalArgumentException("Language not verified by this adapter");
   if(node.has("mode")&&!Set.of("search","taint").contains(node.path("mode").asText()))throw new IllegalArgumentException("Unsupported mode");
   if("taint".equals(node.path("mode").asText())){
    if(!node.path("pattern-sources").isArray()||node.path("pattern-sources").isEmpty()||!node.path("pattern-sinks").isArray()||node.path("pattern-sinks").isEmpty())throw new IllegalArgumentException("Taint sources and sinks required");
   }else if(!node.has("pattern")&&!node.has("patterns")&&!node.has("pattern-either")&&!node.has("pattern-regex"))throw new IllegalArgumentException("Pattern required");
   var result=node.deepCopy();result.put("id",dto.getEngineRuleId());result.put("message",rule.getMessage());result.put("severity","ERROR");return result;
  }catch(java.io.IOException e){throw new IllegalArgumentException("Invalid JSON rule definition");}
 }
}
