package com.tracelink.appsec.module.betterleaks.engine;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.tracelink.appsec.module.betterleaks.allowlist.*;
import com.tracelink.appsec.module.betterleaks.model.*;
import com.tracelink.appsec.module.betterleaks.scanner.BetterleaksScanner;
import com.tracelink.appsec.watchtower.core.process.*;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;

class BetterleaksExecutionIdentityTest {
 @TempDir Path directory;
 @Test void binaryAndAllowlistEditsChangeEvidenceButDoNotCertifyNativeInputs()throws Exception{
  Path binary=directory.resolve("betterleaks");Files.writeString(binary,"synthetic binary evidence v1");
  var runner=mock(ProcessRunner.class);when(runner.run(any())).thenReturn(new ProcessResult(0,"1.8.1","",false,false,false,Duration.ZERO));
  var engine=new BetterleaksEngine(runner,binary.toString());var scanner=new BetterleaksScanner(engine);
  var rule=new BetterleaksProvidedRuleDto();rule.setName("Betterleaks: github-pat");rule.setBetterleaksId("github-pat");rule.setPriority(RulePriority.HIGH);rule.setMessage("Secret guidance");
  var set=new RulesetDto();set.setName("test");set.setRules(Set.of(rule));var config=new CodeScanConfig();config.setRuleset(set);config.setWorkingDirectory(directory);
  var first=engine.getExecutionIdentity(scanner,config,List.of());assertNotNull(first.configurationHash());assertTrue(first.version().startsWith("1.8.1"));assertFalse(first.configurationComplete());assertFalse(first.isReusable());assertFalse(first.toString().contains(directory.toString()));
  var edited=engine.getExecutionIdentity(scanner,config,List.of(new BetterleaksAllowlistEntry(BetterleaksAllowlistScope.GLOBAL,null,"test/**",null)));assertNotEquals(first.configurationHash(),edited.configurationHash());
  Files.writeString(binary,"synthetic binary evidence v2");assertNotEquals(first.configurationHash(),engine.getExecutionIdentity(scanner,config,List.of()).configurationHash());
  when(runner.run(any())).thenReturn(new ProcessResult(0,"unexpected version containing a path","",false,false,false,Duration.ZERO));assertNull(engine.getExecutionIdentity(scanner,config,List.of()).version());
 }
}
