package com.tracelink.appsec.watchtower.core.module;

import java.util.List;
import java.util.Set;
import com.tracelink.appsec.watchtower.core.module.scanner.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.code.report.*;

/** One invocation policy, with fresh checks at execution and publication. */
public final class ControlledCodeScanner implements ICodeScanner {
 private final ICodeScanner delegate;
 private final ModuleControlService controls;
 private ModuleControlService.Policy policy;
 public ControlledCodeScanner(String module,ICodeScanner delegate,ModuleControlService controls){
  this.delegate=delegate;this.controls=controls;this.policy=controls.policy(module);
 }
 public void prepareExecution(){policy=controls.policy(policy.module());}
 public boolean isDisabled(){return !policy.enabled()||!policy.equals(controls.policy(policy.module()));}
 public String executionName(){return java.util.Objects.toString(delegate.executionName(),delegate.getClass().getName());}
 public String setupIssue(){return delegate.setupIssue();}
 public List<Class<? extends RuleDto>> getSupportedRuleClass(){return delegate.getSupportedRuleClass();}
 public ScanScope getRequiredScope(){return delegate.getRequiredScope();}
 public List<String> getRequiredFilePatterns(){return delegate.getRequiredFilePatterns();}
 public Set<String> getExcludedFolders(){return delegate.getExcludedFolders();}
 public boolean isSensitive(){return delegate.isSensitive();}
 public List<String> getDefaultFileTypes(){return delegate.getDefaultFileTypes();}
 /** The admin's choice for this module when there is one (empty means every file), else the scanner's default. */
 public List<String> getFileTypes(){return policy.fileTypes()!=null?policy.fileTypes():delegate.getDefaultFileTypes();}
 public ExecutionCapability getExecutionCapability(){return delegate.getExecutionCapability();}
 public boolean supportsScanType(CodeScanType type){return delegate.supportsScanType(type);}
 public EngineExecutionIdentity getExecutionIdentity(CodeScanConfig config){
  var identity=!isDisabled()?delegate.getExecutionIdentity(config):EngineExecutionIdentity.unknown(executionName());
  if(identity==null)identity=EngineExecutionIdentity.unknown(executionName());
  var builder=RuleRevision.definition("module-policy","v1")
    .field("engine",identity.fingerprint()).field("policyModule",policy.module())
    .field("enabled",Boolean.toString(policy.enabled())).field("version",Long.toString(policy.version()));
  // The types in effect, not just the policy version: a release that changes a default must not reuse old reports.
  // Left out when empty so scanners that run on every file keep their existing identity.
  var types=getFileTypes();
  if(!types.isEmpty())builder.field("fileTypes",String.join(",",types));
  return new EngineExecutionIdentity(identity.engine(),identity.version(),builder.hash(),
    policy.enabled()&&identity.configurationComplete());
 }
 public CodeScanReport scan(CodeScanConfig config){
  if(isDisabled())return unavailable();
  var report=delegate.scan(config);
  return !isDisabled()?report:unavailable();
 }
 private CodeScanReport unavailable(){var report=new CodeScanReport();report.addError(new CodeScanError("Module policy changed or disabled; execution incomplete"));return report;}
}
