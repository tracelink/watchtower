package com.tracelink.appsec.module.opengrep;

import java.util.*;
import com.tracelink.appsec.module.opengrep.model.OpengrepProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.ruleset.*;

/** Original Watchtower examples; no third-party rule pack is silently imported. */
public final class OpengrepCatalog {
 private OpengrepCatalog() { }
 public static List<RulesetDto> rulesets(){
  var set=new RulesetDto();set.setName("Reviewed starter checks");set.setDescription("Original MIT Watchtower pattern checks; review applicability before enforcement.");set.setDesignation(RulesetDesignation.PROVIDED);set.setBlockingLevel(RulePriority.LOW);
  set.setRules(Set.of(rule("watchtower.python.eval","Python eval", "python","eval(...)"),
    rule("watchtower.javascript.eval","JavaScript eval","javascript","eval(...)"),
    rule("watchtower.java.runtime-exec","Java Runtime exec","java","Runtime.getRuntime().exec(...)"),
    rule("watchtower.yaml.privileged","YAML privileged container","yaml","privileged: true")));
  return List.of(set);
 }
 private static OpengrepProvidedRuleDto rule(String id,String name,String language,String pattern){
  var dto=new OpengrepProvidedRuleDto();dto.setEngineRuleId(id);dto.setName("Opengrep: "+name);dto.setMessage("Review "+name+" for unsafe usage; pattern presence alone does not establish exploitability.");
  dto.setExternalUrl("https://github.com/opengrep/opengrep/tree/v1.30.2");dto.setPriority(RulePriority.LOW);dto.setLicense("MIT");dto.setSource("watchtower/opengrep-starter/v1");
  dto.setDefinition(com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory.encode(Map.of("languages",List.of(language),"pattern",pattern)));return dto;
 }
}
