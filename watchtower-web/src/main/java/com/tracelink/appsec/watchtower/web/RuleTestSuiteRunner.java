package com.tracelink.appsec.watchtower.web;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import com.tracelink.appsec.module.regex.model.*;
import com.tracelink.appsec.module.json.model.*;
import com.tracelink.appsec.module.pmd.model.*;
import com.tracelink.appsec.module.eslint.model.*;
import com.tracelink.appsec.module.betterleaks.model.*;
import com.tracelink.appsec.module.checkov.model.*;
import com.tracelink.appsec.module.regex.scanner.RegexScanner;
import com.tracelink.appsec.module.json.scanner.JsonScanner;
import com.tracelink.appsec.module.pmd.scanner.PMDScanner;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.module.eslint.scanner.EsLintScanner;
import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.betterleaks.scanner.BetterleaksScanner;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksEngine;
import com.tracelink.appsec.module.checkov.scanner.CheckovScanner;
import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.candidate.*;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;

/** Data-returning tester reuses the actual engine adapters. It is NOT an application bean.
 * Direct execution uses a bounded subprocess under the user's R3 decision; a future service
 * adapter can invoke the same entry point. This class supplies no security isolation.
 */
public final class RuleTestSuiteRunner {
 private RuleTestSuiteRunner() { }
 public static RuleTestSuite.Result run(RuleTestSuite.Request request) {
  if(request.files()==null||request.files().isEmpty()||request.files().size()>20
    ||RuleDefinitionHistory.encode(request).getBytes(java.nio.charset.StandardCharsets.UTF_8).length>2*1024*1024)
   throw new IllegalArgumentException("Input limit");
  List<RuleTestSuite.Comparison> comparisons=new ArrayList<>();
  com.tracelink.appsec.module.opengrep.scanner.OpengrepScanner shared=null;
  try {
   if("opengrep".equals(request.module()))shared=com.tracelink.appsec.module.opengrep.scanner.OpengrepScanner.reviewedSession();
  for(var file:request.files()) {
   if(file.id()==null||!file.id().matches("[a-f0-9-]{36}")||file.path()==null
     ||!file.path().matches("[A-Za-z0-9][A-Za-z0-9._-]{0,99}")||file.path().contains("..")
     ||file.content()==null||file.content().getBytes(java.nio.charset.StandardCharsets.UTF_8).length>65536)
    throw new IllegalArgumentException("Invalid fixture");
   comparisons.add(new RuleTestSuite.Comparison(file.id(),test(request,request.baseDefinition(),file,shared),test(request,request.candidateDefinition(),file,shared)));
  }
  return new RuleTestSuite.Result(comparisons);
  }catch(java.io.IOException e){throw new IllegalStateException("Reviewed runtime cache unavailable");}
  finally{if(shared!=null)try{shared.close();}catch(java.io.IOException e){throw new IllegalStateException("Reviewed runtime cleanup failed");}}
 }
 /**
  * Variant search (R5.3): scans an existing pinned checkout with one exact definition, using the
  * same engine adapter as normal scans. Deterministic for a given definition, engine and commit.
  * Returns sorted, de-duplicated relative paths and lines only; never source text.
  */
 public static RuleTestSuite.SearchResult search(RuleTestSuite.SearchRequest request) {
  Path root;
  try{root=Path.of(request.directory()).toRealPath();}catch(Exception e){throw new IllegalArgumentException("Checkout unavailable");}
  if(!Files.isDirectory(root))throw new IllegalArgumentException("Checkout unavailable");
  String module=request.module();ICodeScanner engine=null;
  try {
   var dto=RuleDefinitionHistory.JSON.readValue(request.definition(),type(module,request.designation()));
   var ruleset=new RulesetDto();ruleset.setName("Variant search");ruleset.setDescription("Single exact definition");ruleset.setRules(Set.of(dto));
   var config=new CodeScanConfig();config.setWorkingDirectory(root);config.setRuleset(ruleset);config.setThreads(0);
   engine="opengrep".equals(module)?com.tracelink.appsec.module.opengrep.scanner.OpengrepScanner.reviewedSession():scanner(module);
   String identity=RuleDefinitionHistory.encode(engine.getExecutionIdentity(config));
   var report=engine.scan(config);
   if("UNSUPPORTED".equals(report.getExecutionStatus()))return new RuleTestSuite.SearchResult("UNSUPPORTED",List.of(),0,false,identity);
   SortedSet<RuleTestSuite.Location> found=new TreeSet<>(Comparator.comparing(RuleTestSuite.Location::path).thenComparingInt(RuleTestSuite.Location::line));
   for(var finding:report.getViolations()) {
    Path path=Path.of(finding.getFileName());if(!path.isAbsolute())path=root.resolve(path);path=path.normalize();
    if(!path.startsWith(root)||finding.getLineNum()<1)return new RuleTestSuite.SearchResult("FAILED",List.of(),1,false,identity);
    found.add(new RuleTestSuite.Location(root.relativize(path).toString().replace('\\','/'),finding.getLineNum()));
   }
   boolean truncated=found.size()>RuleTestSuite.MAX_SEARCH_LOCATIONS;
   int errors=report.getErrors().size();
   return new RuleTestSuite.SearchResult(errors==0?"COMPLETE":"PARTIAL",found.stream().limit(RuleTestSuite.MAX_SEARCH_LOCATIONS).toList(),errors,truncated,identity);
  }catch(IllegalArgumentException e){throw e;}
  catch(Exception e){return new RuleTestSuite.SearchResult("FAILED",List.of(),1,false,"direct-v1");}
  finally{if(engine instanceof AutoCloseable closeable)try{closeable.close();}catch(Exception e){throw new IllegalStateException("Reviewed runtime cleanup failed");}}
 }
 private static Class<? extends RuleDto> type(String module,String designation) {
  boolean custom="CUSTOM".equals(designation);
  if(!custom&&!"PROVIDED".equals(designation))throw new IllegalArgumentException("Unsupported designation");
  return switch(module) {
   case "opengrep" -> custom?com.tracelink.appsec.module.opengrep.model.OpengrepCustomRuleDto.class:com.tracelink.appsec.module.opengrep.model.OpengrepProvidedRuleDto.class;
   case "regex" -> custom?RegexCustomRuleDto.class:RegexProvidedRuleDto.class;
   case "json" -> JsonRuleDto.class;
   case "pmd" -> custom?PMDCustomRuleDto.class:PMDProvidedRuleDto.class;
   case "eslint" -> custom?EsLintCustomRuleDto.class:EsLintProvidedRuleDto.class;
   case "betterleaks" -> custom?BetterleaksCustomRuleDto.class:BetterleaksProvidedRuleDto.class;
   case "checkov" -> {if(custom)throw new IllegalArgumentException("Checkov custom authoring unavailable");yield CheckovProvidedRuleDto.class;}
   default -> throw new IllegalArgumentException("Unsupported engine");
  };
 }
 private static ICodeScanner scanner(String module) {
  return switch(module) {
   case "opengrep" -> new com.tracelink.appsec.module.opengrep.scanner.OpengrepScanner();
   case "regex" -> new RegexScanner();
   case "json" -> new JsonScanner();
   case "pmd" -> new PMDScanner(new PMDRuleService(null));
   case "eslint" -> new EsLintScanner(new LinterEngine());
   case "betterleaks" -> new BetterleaksScanner(new BetterleaksEngine());
   case "checkov" -> new CheckovScanner(new CheckovEngine());
   default -> throw new IllegalArgumentException("Unsupported engine");
  };
 }
 private static RuleTestResult test(RuleTestSuite.Request request,String definition,RuleTestSuite.File fixture,ICodeScanner shared) {
  Path root=null;long started=System.nanoTime();String module=request.module();
  try {
   var dto=RuleDefinitionHistory.JSON.readValue(definition,type(module,request.designation()));
   root=Files.createTempDirectory("watchtower-reviewed-fixture-").toRealPath();
   Files.writeString(root.resolve(fixture.path()),fixture.content());
   var ruleset=new RulesetDto();ruleset.setName("Reviewed rule test");ruleset.setDescription("Single exact definition");ruleset.setRules(Set.of(dto));
   var config=new CodeScanConfig();config.setWorkingDirectory(root);config.setRuleset(ruleset);config.setThreads(0);
   if(dto instanceof com.tracelink.appsec.module.regex.model.RegexRuleDto regex&&!regex.isValidExtension(fixture.path())
     ||dto instanceof JsonRuleDto json&&!json.isValidExtension(fixture.path()))
    return RuleTestResult.failed("UNSUPPORTED",module,"direct-v1","Fixture extension is excluded by this revision");
   var engine=shared==null?scanner(module):shared;var identity=engine.getExecutionIdentity(config);
   var report=engine.scan(config);if("UNSUPPORTED".equals(report.getExecutionStatus()))return RuleTestResult.failed("UNSUPPORTED",module,"direct-v1","No fixture target was evaluated");var matches=new ArrayList<RuleTestResult.Match>();
   if(report.getViolations().size()>200)return RuleTestResult.failed("LIMIT",module,"direct-v1","Match output exceeded 200 locations");
   for(var finding:report.getViolations()) {
    Path path=Path.of(finding.getFileName());if(!path.isAbsolute())path=root.resolve(path);
    if(!path.normalize().equals(root.resolve(fixture.path()))||finding.getLineNum()<1)
     return RuleTestResult.failed("FAILED",module,"direct-v1","Engine returned an unavailable location");
    matches.add(new RuleTestResult.Match(fixture.path(),finding.getLineNum(),RuleDefinitionHistory.hash(Objects.toString(finding.getMessage(),""))));
   }
   matches.sort(Comparator.comparingInt(RuleTestResult.Match::line).thenComparing(RuleTestResult.Match::messageKey));
   int errors=report.getErrors().size();
   return new RuleTestResult(errors==0?"COMPLETE":"FAILED",module,RuleDefinitionHistory.encode(identity),matches,errors,
     (System.nanoTime()-started)/1000000,"Single fixture; direct execution is not sandboxed. Incomplete engine provenance stays unknown.");
  } catch(Exception e) { return RuleTestResult.failed("FAILED",module,"direct-v1","Engine could not evaluate this definition/fixture; no clean result is inferred"); }
  finally {
   if(root!=null)try(var paths=Files.walk(root)) {
    for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);
   }catch(java.io.IOException e){throw new IllegalStateException("Fixture cleanup failed");}
  }
 }
 /** Fixed input/output entry point for a tester process; starts no Spring application. */
 public static void main(String[] ignored) {
  var output=System.out;
  System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
  System.setErr(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
  ((ch.qos.logback.classic.Logger)org.slf4j.LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME)).setLevel(ch.qos.logback.classic.Level.OFF);
  try {
   Path file=Path.of(System.getProperty("watchtower.rule-test.input","/input/request.json"));if(Files.size(file)>2*1024*1024)throw new IllegalArgumentException("Input limit");
   if("search".equals(System.getProperty("watchtower.rule-test.mode")))output.print(RuleDefinitionHistory.encode(search(RuleDefinitionHistory.JSON.readValue(Files.readAllBytes(file),RuleTestSuite.SearchRequest.class))));
   else output.print(RuleDefinitionHistory.encode(run(RuleDefinitionHistory.JSON.readValue(Files.readAllBytes(file),RuleTestSuite.Request.class))));
  }catch(Exception e){System.exit(1);}
 }
}
