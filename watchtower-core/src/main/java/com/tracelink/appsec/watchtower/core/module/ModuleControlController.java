package com.tracelink.appsec.watchtower.core.module;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.stereotype.Controller;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import com.tracelink.appsec.watchtower.core.metrics.ModuleStatus;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleEditorService;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;

@Controller @PreAuthorize("hasAuthority('Module Settings Modify')")
public class ModuleControlController {
 private final ModuleControlService controls;
 private final ScanRegistrationService registry;
 private final RuleService rules;
 private final RuleEditorService ruleEditors;
 public ModuleControlController(ModuleControlService controls,ScanRegistrationService registry,RuleService rules,RuleEditorService ruleEditors){this.controls=controls;this.registry=registry;this.rules=rules;this.ruleEditors=ruleEditors;}
 @GetMapping("/configuration/modules")
 @PreAuthorize("hasAnyAuthority('Module Settings View','Module Settings Modify')")
 public WatchtowerModelAndView page(Authentication auth){
  var mv=new WatchtowerModelAndView("configuration/modules");mv.addScriptReference("/scripts/module-controls.js");
  // View alone shows the page; the switches and file-type buttons stay off (writes also need Modify)
  mv.addObject("canModify",auth!=null&&auth.getAuthorities().stream().anyMatch(a->"Module Settings Modify".equals(a.getAuthority())));
  List<ModuleRow> rows=rows();
  mv.addObject("modules",rows);
  mv.addObject("readyCount",rows.stream().filter(r->ModuleStatus.READY.equals(r.status().state())).count());
  mv.addObject("setupCount",rows.stream().filter(r->ModuleStatus.SETUP.equals(r.status().state())).count());
  mv.addObject("offCount",rows.stream().filter(r->ModuleStatus.OFF.equals(r.status().state())).count());
  return mv;
 }
 /** Every registered module with the status Home shows, its policy and its rule count. */
 private List<ModuleRow> rows(){
  Map<String,Long> counts=rules.countRulesByModule();
  Set<String> editable=new TreeSet<>(String.CASE_INSENSITIVE_ORDER);editable.addAll(ruleEditors.getKnownModules());
  List<ModuleRow> rows=new ArrayList<>();
  registry.getScannersByModule().forEach((module,scanner)->{
   var policy=controls.policy(module);String key=module.toLowerCase(Locale.ROOT);
   List<String> types=scanner instanceof ICodeScanner code?code.getFileTypes():List.of();
   List<String> defaults=scanner instanceof ICodeScanner code?code.getDefaultFileTypes():List.of();
   rows.add(new ModuleRow(policy.module(),ModuleStatus.of(module,scanner),policy.enabled(),policy.version(),
     counts.getOrDefault(key,0L),editable.contains(module)?"/rule/edit/"+key:null,
     types==null?List.of():types,defaults==null?List.of():defaults,policy.fileTypes()!=null));
  });
  return List.copyOf(rows);
 }
 /** Saves the file types a module's scanner runs on; useDefault returns to the scanner's own types. */
 @PostMapping("/configuration/modules/file-types")
 public String changeFileTypes(@RequestParam String module,@RequestParam long version,
   @RequestParam(defaultValue="") String fileTypes,@RequestParam(defaultValue="false") boolean useDefault,
   Authentication auth,RedirectAttributes redirect){
  if(registry.getScannerNames().stream().noneMatch(n->n.equalsIgnoreCase(module))){
   // A name that is not a module is a bad request, not a server error
   redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,"Unknown module.");
   return "redirect:/configuration/modules";
  }
  List<String> typed=useDefault?null:java.util.Arrays.stream(fileTypes.split("[,\\s]+")).filter(t->!t.isBlank()).toList();
  try {
   controls.changeFileTypes(module,typed,version,auth.getName());
   redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,useDefault?"Back to the default file types. Applies to the next scans.":"File types saved. Applies to the next scans.");
  } catch(IllegalArgumentException invalid) {
   redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,invalid.getMessage());
  }
  return "redirect:/configuration/modules";
 }
 @PostMapping("/configuration/modules")
 public String change(@RequestParam String module,@RequestParam boolean enabled,@RequestParam long version,Authentication auth,RedirectAttributes redirect){
  if(registry.getScannerNames().stream().noneMatch(n->n.equalsIgnoreCase(module))){
   redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,"Unknown module.");
   return "redirect:/configuration/modules";
  }
  controls.change(module,enabled,version,auth.getName());redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,(enabled?"Turned on. ":"Turned off. ")+"Queued work uses the current setting; running work rechecks before publishing.");return "redirect:/configuration/modules";
 }
}
