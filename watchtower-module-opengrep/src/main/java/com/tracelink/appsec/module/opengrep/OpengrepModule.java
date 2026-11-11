package com.tracelink.appsec.module.opengrep;

import java.util.List;
import com.tracelink.appsec.module.opengrep.scanner.OpengrepScanner;
import com.tracelink.appsec.watchtower.core.module.*;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.*;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

@WatchtowerModule
public class OpengrepModule extends AbstractCodeScanModule {
 public static final String VERSION="1.30.2";
 public static final String EDIT="Opengrep Rule Editor";
 public static final String DESIGN="Opengrep Rule Designer";
 private final OpengrepDesigner designer;
 public OpengrepModule(OpengrepDesigner designer){this.designer=designer;}
 public String getName(){return "Opengrep";}
 public String getSchemaHistoryTable(){return "opengrep_schema_history";}
 public String getMigrationsLocation(){return "db/opengrep";}
 public ICodeScanner getScanner(){return new OpengrepScanner();}
 public IRuleDesigner getRuleDesigner(){return designer;}
 public IRuleEditor getRuleEditor(){return new IRuleEditor(){
  public String getPrivilegeNameForAccess(){return EDIT;}
  public RuleEditModelAndView getDefaultRuleEditModelAndView(com.tracelink.appsec.watchtower.core.rule.RuleDto rule){
   var mv=new RuleEditModelAndView("rule-edit/opengrep");mv.addObject("rule",rule);mv.addObject("priorities",com.tracelink.appsec.watchtower.core.rule.RulePriority.values());return mv;
  }
 };}
 public List<PrivilegeEntity> getModulePrivileges(){return List.of(
  new PrivilegeEntity().setName(EDIT).setCategory("Rule Editor").setDescription("Edit Opengrep rules and enforcement priority."),
  new PrivilegeEntity().setName(DESIGN).setCategory("Rule Designer").setDescription("Author Opengrep rules for human reviewed testing."));}
 public List<RulesetDto> getProvidedRulesets(){return OpengrepCatalog.rulesets();}
}
