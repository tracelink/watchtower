package com.tracelink.appsec.watchtower.core.module;

import java.util.List;
import com.tracelink.appsec.watchtower.core.module.scanner.IImageScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;
import com.tracelink.appsec.watchtower.core.scan.image.report.*;

public final class ControlledImageScanner implements IImageScanner {
 private final IImageScanner delegate;
 private final ModuleControlService controls;
 private ModuleControlService.Policy policy;
 public ControlledImageScanner(String module,IImageScanner delegate,ModuleControlService controls){this.delegate=delegate;this.controls=controls;policy=controls.policy(module);}
 public void prepareExecution(){policy=controls.policy(policy.module());}
 public boolean isDisabled(){return !policy.enabled()||!policy.equals(controls.policy(policy.module()));}
 public String executionName(){return java.util.Objects.toString(delegate.executionName(),delegate.getClass().getName());}
 public String setupIssue(){return delegate.setupIssue();}
 public List<Class<? extends RuleDto>> getSupportedRuleClass(){return delegate.getSupportedRuleClass();}
 public ImageScanReport scan(ImageScanConfig config){
  if(isDisabled())return unavailable();var report=delegate.scan(config);return isDisabled()?unavailable():report;
 }
 private ImageScanReport unavailable(){var report=new ImageScanReport();report.addError(new ImageScanError("Module policy changed or disabled; execution incomplete"));return report;}
}
