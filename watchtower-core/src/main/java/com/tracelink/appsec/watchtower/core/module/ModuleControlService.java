package com.tracelink.appsec.watchtower.core.module;

import java.util.List;
import java.util.Locale;
import com.tracelink.appsec.watchtower.core.scan.code.ScannerFileTypes;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@Service
public class ModuleControlService {
 /** {@code fileTypes} is null while the scanner's own default applies; an empty list means every file. */
 public record Policy(String module,boolean enabled,long version,List<String> fileTypes) {
  public Policy(String module,boolean enabled,long version){this(module,enabled,version,null);}
 }
 private final ModuleSettingRepository settings;
 @org.springframework.beans.factory.annotation.Autowired
 private com.tracelink.appsec.watchtower.core.persistence.LedgerRepository records;
 @Transactional
 public void register(String module){
  String key=module.toLowerCase(Locale.ROOT);if(settings.existsById(key))return;
  records.lockScope("module-settings");
  if(!settings.existsById(key))settings.saveAndFlush(new ModuleSettingEntity(key,!key.equals("opengrep")));
 }
 public ModuleControlService(ModuleSettingRepository settings){this.settings=settings;}
 @Transactional(readOnly=true)
 public Policy policy(String module){
  String key=module.toLowerCase(Locale.ROOT);
  return settings.findById(key).map(r->new Policy(key,r.isEnabled(),r.getVersion(),parseFileTypes(r.getFileTypes())))
    .orElseGet(()->new Policy(key,!key.equals("opengrep"),0));
 }
 private static List<String> parseFileTypes(String stored){
  if(stored==null)return null;
  return stored.isBlank()?List.of():List.of(stored.split(","));
 }
 @Transactional(readOnly=true)
 public String fingerprint(){return com.tracelink.appsec.watchtower.core.rule.RuleRevision.definition("module-policies","v1")
  .unordered("policies",settings.findAll().stream().map(r->r.getModule()+"/"+r.isEnabled()+"/"+r.getVersion()+(r.getFileTypes()==null?"":"/"+r.getFileTypes())).toList()).hash();}
 public boolean enabled(String module){return policy(module).enabled();}
 @Transactional
 public void change(String module,boolean enabled,long version,String actor){
  var row=settings.findById(module.toLowerCase(Locale.ROOT))
    .orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Module policy unavailable"));
  if(row.getVersion()!=version)throw new ResponseStatusException(HttpStatus.CONFLICT,"Module policy changed; reload");
  row.change(enabled,actor);settings.saveAndFlush(row);
 }
 /**
  * Sets the file types a module's scanner runs on.
  *
  * @param types the types as entered; null returns to the scanner's default, an empty list means every file
  * @throws IllegalArgumentException if a type is not valid
  */
 @Transactional
 public void changeFileTypes(String module,List<String> types,long version,String actor){
  List<String> cleaned=types==null?null:ScannerFileTypes.normalize(types);
  var row=settings.findById(module.toLowerCase(Locale.ROOT))
    .orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Module policy unavailable"));
  if(row.getVersion()!=version)throw new ResponseStatusException(HttpStatus.CONFLICT,"Module policy changed; reload");
  row.changeFileTypes(cleaned==null?null:String.join(",",cleaned),actor);settings.saveAndFlush(row);
 }
 public void requireEnabled(String module){if(!enabled(module))throw new ResponseStatusException(HttpStatus.CONFLICT,"This module is disabled");}
}
