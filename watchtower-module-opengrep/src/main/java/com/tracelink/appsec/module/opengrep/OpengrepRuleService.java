package com.tracelink.appsec.module.opengrep;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.module.opengrep.model.*;
import com.tracelink.appsec.module.opengrep.repository.OpengrepRuleRepository;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.module.ModuleControlService;

@Service
public class OpengrepRuleService implements CustomRuleValidator {
 private final OpengrepRuleRepository repository;
 private final RuleService rules;
 private final ModuleControlService controls;
 public OpengrepRuleService(OpengrepRuleRepository repository,@org.springframework.context.annotation.Lazy RuleService rules,ModuleControlService controls){this.repository=repository;this.rules=rules;this.controls=controls;}
 public boolean supports(RuleDto rule){return rule instanceof OpengrepRuleDto;}
 public void validate(RuleDto rule)throws RuleException {
  try{
   OpengrepDefinition.parse(rule);
   var existing=rules.getRule(rule.getName());
   if(existing instanceof OpengrepRuleEntity opengrep && !opengrep.getEngineRuleId().equals(((OpengrepRuleDto)rule).getEngineRuleId()))throw new IllegalArgumentException("Stable engine rule ID cannot change on import");
  }catch(IllegalArgumentException e){throw new RuleException(e.getMessage());}
 }
 @Transactional
 public void create(OpengrepCustomRuleDto dto)throws RuleException {
  controls.requireEnabled("Opengrep");validate(dto);
  if(rules.getRule(dto.getName())!=null)throw new RuleException("Rule name already exists");
  repository.saveAndFlush(dto.toEntity());rules.invalidateRuleCache();
 }
 @Transactional
 public void edit(OpengrepCustomRuleDto dto)throws RuleException {
  var entity=repository.findById(dto.getId()).orElseThrow(()->new IllegalArgumentException("Rule unavailable"));
  if(!entity.isProvided()){
   validate(dto);if(rules.createsNameCollision(dto.getId(),dto.getName()))throw new RuleException("Rule name already exists");
   if(!entity.getEngineRuleId().equals(dto.getEngineRuleId()))throw new RuleException("Stable engine rule ID cannot change");
   entity.setName(dto.getName());entity.setDefinition(dto.getDefinition());entity.setMessage(dto.getMessage());entity.setExternalUrl(dto.getExternalUrl());
   entity.setLicense(dto.getLicense());entity.setSource(dto.getSource());
  }
  entity.setPriority(dto.getPriority());repository.saveAndFlush(entity);rules.invalidateRuleCache();
 }
}
