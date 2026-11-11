package com.tracelink.appsec.module.opengrep;

import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import com.tracelink.appsec.module.opengrep.model.OpengrepCustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@Controller
public class OpengrepController {
 private final OpengrepRuleService rules;
 public OpengrepController(OpengrepRuleService rules){this.rules=rules;}
 @PostMapping("/designer/opengrep/save") @PreAuthorize("hasAuthority('Opengrep Rule Designer')")
 public String save(@Valid OpengrepCustomRuleDto dto,BindingResult result,Authentication auth,RedirectAttributes redirect){
  dto.setAuthor(auth.getName());
  try{if(result.hasErrors())throw new RuleException("Complete the required fields");rules.create(dto);redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,"Rule saved. Register reviewed fixtures in Test improvements before adding it to enforcement.");}
  catch(RuleException e){redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,e.getMessage());}
  return "redirect:/designer/opengrep";
 }
 @PostMapping("/rule/edit/opengrep") @PreAuthorize("hasAuthority('Opengrep Rule Editor')")
 public String edit(@Valid OpengrepCustomRuleDto dto,BindingResult result,RedirectAttributes redirect){
  try{if(result.hasErrors())throw new RuleException("Complete the required fields");rules.edit(dto);redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,"Rule saved");}
  catch(RuleException e){redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,e.getMessage());}
  return "redirect:/rule/edit/opengrep/"+dto.getId();
 }
}
