package com.tracelink.appsec.module.opengrep.model;

import jakarta.validation.constraints.*;
import com.tracelink.appsec.watchtower.core.rule.*;

public class OpengrepCustomRuleDto extends CustomRuleDto implements OpengrepRuleDto {
 @NotBlank @Pattern(regexp="[A-Za-z][A-Za-z0-9._-]{0,149}") private String engineRuleId;
 @NotBlank @Size(max=60000) private String definition;
 @NotBlank @Size(max=100) private String license;
 @NotBlank @Size(max=255) private String source;
 public String getEngineRuleId(){return engineRuleId;}
 public void setEngineRuleId(String value){engineRuleId=value;}
 public String getDefinition(){return definition;}
 public void setDefinition(String value){definition=value;}
 public String getLicense(){return license;}
 public void setLicense(String value){license=value;}
 public String getSource(){return source;}
 public void setSource(String value){source=value;}
 
 public String getModule(){return "Opengrep";}
 public String getExternalRuleKey(){return engineRuleId;}
 protected RuleRevision executableDefinition(){return newDefinition().field("engineRuleId",engineRuleId).field("definition",definition);}
 public OpengrepRuleEntity toEntity(){
  var e=new OpengrepRuleEntity();e.setName(getName());e.setAuthor(getAuthor());e.setMessage(getMessage());e.setExternalUrl(getExternalUrl());e.setPriority(getPriority());
  e.setProvided(isProvided());e.setEngineRuleId(engineRuleId);e.setDefinition(definition);e.setLicense(license);e.setSource(source);return e;
 }
}
