package com.tracelink.appsec.module.opengrep.model;

import jakarta.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import java.util.stream.Collectors;

@Entity @Table(name="opengrep_rules") @PrimaryKeyJoinColumn(name="rule_id")
public class OpengrepRuleEntity extends RuleEntity {
 @Column(name="engine_rule_id") private String engineRuleId;
 @Column(name="definition_json",columnDefinition="TEXT") private String definition;
 @Column(name="rule_license") private String license;
 @Column(name="rule_source") private String source;
 private boolean provided;
 public String getEngineRuleId(){return engineRuleId;}
 public void setEngineRuleId(String value){engineRuleId=value;}
 public String getDefinition(){return definition;}
 public void setDefinition(String value){definition=value;}
 public String getLicense(){return license;}
 public void setLicense(String value){license=value;}
 public String getSource(){return source;}
 public void setSource(String value){source=value;}
 public boolean isProvided(){return provided;}
 public void setProvided(boolean value){provided=value;}
 public RuleDto toDto(){
  RuleDto dto;
  if(provided){var p=new OpengrepProvidedRuleDto();p.setEngineRuleId(engineRuleId);p.setDefinition(definition);p.setLicense(license);p.setSource(source);p.setMessage(getMessage());p.setExternalUrl(getExternalUrl());dto=p;}
  else{var c=new OpengrepCustomRuleDto();c.setEngineRuleId(engineRuleId);c.setDefinition(definition);c.setLicense(license);c.setSource(source);c.setMessage(getMessage());c.setExternalUrl(getExternalUrl());c.setAuthor(getAuthor());dto=c;}
  dto.setId(getId());dto.setName(getName());dto.setPriority(getPriority());dto.setRulesets(getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));return withStewardship(dto);
 }
}
