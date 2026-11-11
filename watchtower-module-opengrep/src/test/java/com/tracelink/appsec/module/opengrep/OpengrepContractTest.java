package com.tracelink.appsec.module.opengrep;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.tracelink.appsec.module.opengrep.model.*;
import com.tracelink.appsec.module.opengrep.scanner.OpengrepScanner;
import com.tracelink.appsec.watchtower.core.process.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.*;

class OpengrepContractTest {
 @TempDir Path root;
 Path binary(){String value=System.getenv("WATCHTOWER_OPENGREP_PATH");Assumptions.assumeTrue(value!=null,"Pinned binary required for runtime contracts");return Path.of(value);}
 CodeScanConfig config(RuleDto... selected){var set=new RulesetDto();set.setRules(Set.of(selected));var config=new CodeScanConfig();config.setWorkingDirectory(root);config.setRuleset(set);return config;}
 OpengrepCustomRuleDto custom(String definition){var dto=new OpengrepCustomRuleDto();dto.setEngineRuleId("reviewed.taint");dto.setDefinition(definition);dto.setLicense("MIT");dto.setSource("reviewed/fixture-v1");dto.setName("Reviewed rule");dto.setMessage("Review finding");dto.setPriority(RulePriority.HIGH);dto.setAuthor("reviewer");dto.setExternalUrl("https://example.test/rule");return dto;}
 @Test void originalLicensedCatalogAndSingleLocalDefinitionsPreserveStableIdentity(){
  var set=OpengrepCatalog.rulesets().getFirst();assertEquals(4,set.getRules().size());
  for(var rule:set.getRules()){var dto=(OpengrepRuleDto)rule;assertEquals("MIT",dto.getLicense());assertEquals(dto.getEngineRuleId(),rule.getExternalRuleKey());assertNotNull(rule.getRevision());assertEquals(rule.getRevision(),rule.toEntity().toDto().getRevision());OpengrepDefinition.parse(rule);}
  assertEquals(Set.of("javascript","typescript"),custom("{\"languages\":[\"typescript\",\"javascript\"],\"pattern\":\"eval(...)\"}").scannedLanguages());assertEquals(Set.of(),custom("not json").scannedLanguages());
  var dto=custom("{\"languages\":[\"python\"],\"pattern\":\"eval(...)\"}");String revision=dto.getRevision();dto.setName("Renamed");assertEquals(revision,dto.getRevision());dto.setDefinition("{\"languages\":[\"python\"],\"pattern\":\"exec(...)\"}");assertNotEquals(revision,dto.getRevision());
  for(String invalid:List.of("[]","{\"languages\":[\"unknown\"],\"pattern\":\"eval(...)\"}","{\"languages\":[\"python\"],\"mode\":\"extract\"}","{\"languages\":[\"python\"],\"fix\":\"changed\"}","{\"languages\":[\"python\"],\"mode\":\"taint\"}")){dto.setDefinition(invalid);assertThrows(IllegalArgumentException.class,()->OpengrepDefinition.parse(dto));}
 }
 @Test void pinnedRuntimeMatchesFiveLanguagesAndCrossFunctionTaintWithCleanAndCrossFileControls()throws Exception {
  var observed=new java.util.concurrent.atomic.AtomicReference<ProcessResult>();
  var process=new ProcessRunner(){public ProcessResult run(ProcessRequest request) {var result=super.run(request);observed.set(result);return result;}};
  var scanner=new OpengrepScanner(process,binary());
  Files.writeString(root.resolve("case.py"),"match user_input:\n    case value:\n        eval(value)\n");Files.writeString(root.resolve("case.js"),"eval(userInput);\n");Files.writeString(root.resolve("Case.java"),"record Case(String input) { void run() throws Exception { Runtime.getRuntime().exec(input); } }\n");Files.writeString(root.resolve("case.yaml"),"securityContext:\n  privileged: true\n---\nsecurityContext:\n  privileged: false\n");Files.writeString(root.resolve("case.ts"),"eval(userInput as string);\n");
  var ts=custom("{\"languages\":[\"typescript\"],\"pattern\":\"eval(...)\"}");ts.setName("TypeScript");ts.setEngineRuleId("reviewed.typescript");
  var selected=new HashSet<>(OpengrepCatalog.rulesets().getFirst().getRules());selected.add(ts);
  var cfg=config(selected.toArray(RuleDto[]::new));var report=scanner.scan(cfg);assertTrue(report.getErrors().isEmpty(),()->"exit="+observed.get().exitCode()+", timeout="+observed.get().timedOut()+", elapsed="+observed.get().elapsed()+", diagnostics="+observed.get().stderr());assertEquals(6,report.getViolations().size());assertEquals(2,report.getViolations().stream().filter(v->v.getFileName().endsWith("case.ts")).count());
  assertTrue(report.getViolations().stream().allMatch(v->v.getRuleIdentity()!=null&&v.getRuleIdentity().externalRuleKey()!=null&&v.getLineNum()>0));
  assertFalse(scanner.getExecutionIdentity(cfg).isReusable());
  try(var files=Files.list(root)){for(var file:files.toList())Files.delete(file);}
  Files.writeString(root.resolve("taint.py"),"def input_value():\n    return source()\ndef pass_value(value):\n    return value\ndef run():\n    sink(pass_value(input_value()))\n    sink(sanitize(input_value()))\n    sink('clean')\n");
  Files.writeString(root.resolve("taint.js"),"function inputValue() { return source(); }\nfunction passValue(v) { return v; }\nfunction run() { sink(passValue(inputValue())); sink(sanitize(inputValue())); sink('clean'); }\n");
  Files.writeString(root.resolve("other.py"),"def exported():\n    return source()\n");Files.writeString(root.resolve("caller.py"),"from other import exported\ndef run():\n    sink(exported())\n");
  var taint=custom("{\"languages\":[\"python\",\"javascript\"],\"mode\":\"taint\",\"pattern-sources\":[{\"pattern\":\"source(...)\"}],\"pattern-sinks\":[{\"pattern\":\"sink(...)\"}],\"pattern-sanitizers\":[{\"pattern\":\"sanitize(...)\"}]}");
  var taintReport=scanner.scan(config(taint));assertTrue(taintReport.getErrors().isEmpty());assertEquals(2,taintReport.getViolations().size());assertTrue(taintReport.getViolations().stream().noneMatch(v->v.getFileName().endsWith("caller.py")));
  Files.writeString(root.resolve("broken.py"),"def broken(\n eval(value)\n");
  var syntax=custom("{\"languages\":[\"python\"],\"pattern\":\"eval(...)\"}");assertFalse(scanner.scan(config(syntax)).getErrors().isEmpty());
 }
 @Test void processErrorsMalformedEvidenceLimitsAndUnknownIdsNeverBecomeCleanResults()throws Exception {
  var process=mock(ProcessRunner.class);var scanner=new OpengrepScanner(process,binary());var dto=custom("{\"languages\":[\"python\"],\"pattern\":\"eval(...)\"}");var cfg=config(dto);
  String good="{\"results\":[],\"errors\":[],\"paths\":{\"scanned\":[\"case.py\"]}}";
  for(var result:List.of(new ProcessResult(2,good,"raw-private-diagnostic",false,false,false,Duration.ZERO),new ProcessResult(0,good,"",true,false,false,Duration.ZERO),new ProcessResult(0,good,"",false,true,false,Duration.ZERO),new ProcessResult(0,"{}","",false,false,false,Duration.ZERO),new ProcessResult(0,"{\"results\":[],\"errors\":[{}],\"paths\":{\"scanned\":[\"case.py\"]}}","",false,false,false,Duration.ZERO))){
   when(process.run(any())).thenReturn(new ProcessResult(0,"1.30.2\n","",false,false,false,Duration.ZERO),result);
   var report=scanner.scan(cfg);assertEquals(0,report.getViolations().size());assertEquals(1,report.getErrors().size());assertFalse(report.getErrors().getFirst().getErrorMessage().contains("private"));
  }
  when(process.run(any())).thenReturn(new ProcessResult(0,"1.30.2\n","",false,false,false,Duration.ZERO),new ProcessResult(0,good,"",false,false,false,Duration.ZERO));assertTrue(scanner.scan(cfg).getErrors().isEmpty());
  Files.writeString(root.resolve("case.py"),"eval(value)\n");
  String unknown="{\"results\":[{\"check_id\":\"unknown.rule\",\"path\":\"case.py\",\"start\":{\"line\":1}}],\"errors\":[],\"paths\":{\"scanned\":[\"case.py\"]}}";
  when(process.run(any())).thenReturn(new ProcessResult(0,"1.30.2\n","",false,false,false,Duration.ZERO),new ProcessResult(0,unknown,"",false,false,false,Duration.ZERO));assertFalse(scanner.scan(cfg).getErrors().isEmpty());
  String unsupported="{\"results\":[],\"errors\":[],\"paths\":{\"scanned\":[]}}";
  when(process.run(any())).thenReturn(new ProcessResult(0,"1.30.2\n","",false,false,false,Duration.ZERO),new ProcessResult(0,unsupported,"",false,false,false,Duration.ZERO));
  var noTargets=scanner.scan(cfg);assertEquals("UNSUPPORTED",noTargets.getExecutionStatus());assertTrue(noTargets.getErrors().isEmpty());
  var absent=new OpengrepScanner(process,root.resolve("missing"));assertFalse(absent.scan(cfg).getErrors().isEmpty());assertFalse(absent.getExecutionIdentity(cfg).isReusable());
 }
}
