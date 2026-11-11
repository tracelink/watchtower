package com.tracelink.appsec.module.opengrep;

import org.springframework.stereotype.Component;
import com.tracelink.appsec.module.opengrep.scanner.OpengrepScanner;
import com.tracelink.appsec.watchtower.core.rule.candidate.RuleRuntimeAvailability;
@Component
public class OpengrepRuntimeAvailability implements RuleRuntimeAvailability {
 public String module(){return "Opengrep";}
 public boolean available(){return new OpengrepScanner().pinnedBinaryAvailable();}
 public String executionIdentity(){return com.tracelink.appsec.watchtower.core.rule.RuleRevision.definition("opengrep-reviewed-runtime","v1")
  .field("runtime",new OpengrepScanner().getExecutionIdentity(new com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig()).fingerprint())
  .field("cache","private-reviewed-suite").hash();}
}
