package com.tracelink.appsec.watchtower.web;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.watchtower.core.process.ProcessRunner;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.rule.candidate.*;

/** Executes real trusted fixture definitions through the same subprocess entry point as the app. */
class RuleCandidateRuntimeTest {
 @TempDir Path temporary;
 private void common(CustomRuleDto r){r.setId(1L);r.setName("runtime contract");r.setAuthor("engineer");r.setPriority(RulePriority.HIGH);r.setMessage("Finding");r.setExternalUrl("https://example.test/rule");}
 private RuleTestSuite.Request request(RuleDto active,RuleDto candidate,String path,String source){return new RuleTestSuite.Request(active.getModule().toLowerCase(Locale.ROOT),"CUSTOM",RuleDefinitionHistory.definition(active),RuleDefinitionHistory.definition(candidate),List.of(new RuleTestSuite.File(UUID.randomUUID().toString(),path,source)));}
 @Test void directSubprocessReturnsExactRegexLocationsErrorsAndExclusionWithoutSourcePersistence()throws Exception {
  var client=new DirectRuleTestClient(new ProcessRunner(),true,temporary.toString());assertTrue(client.available());assertEquals(64,client.executionIdentity().length());
  var active=new RegexCustomRuleDto();common(active);active.setFileExtension(".txt");active.setRegexPattern("unsafe|risky");
  var candidate=new RegexCustomRuleDto();common(candidate);candidate.setFileExtension(".txt");candidate.setRegexPattern("risky");
  var result=client.test(request(active,candidate,"case-v1.txt","risky\nunsafe\nclean"));var pair=result.cases().getFirst();
  assertTrue(pair.base().complete());assertTrue(pair.candidate().complete());assertEquals(List.of(1,2),pair.base().matches().stream().map(RuleTestResult.Match::line).toList());assertEquals(1,pair.candidate().matches().size());
  assertFalse(RuleDefinitionHistory.encode(result).contains("unsafe"));
  candidate.setRegexPattern("[");assertFalse(client.test(request(active,candidate,"case-v1.txt","clean")).cases().getFirst().candidate().complete());
  assertEquals("UNSUPPORTED",client.test(request(active,active,"excluded.java","risky")).cases().getFirst().base().status());
  try(var paths=java.nio.file.Files.list(temporary)){assertEquals(0,paths.count());}
 }
 @Test void directorySearchReturnsOnlySortedRelativeLocationsAcrossNestedFiles()throws Exception {
  Path checkout=java.nio.file.Files.createDirectories(temporary.resolve("checkout/src/app"));
  java.nio.file.Files.writeString(checkout.resolve("Orders.txt"),"ok\nquery = \"SELECT \" + id\nok\n");
  java.nio.file.Files.writeString(temporary.resolve("checkout/Billing.txt"),"query = \"SELECT \" + other\n");
  java.nio.file.Files.writeString(temporary.resolve("checkout/Clean.txt"),"prepared statement only\n");
  var rule=new RegexCustomRuleDto();common(rule);rule.setFileExtension(".txt");rule.setRegexPattern("\"SELECT \" \\+");
  var request=new RuleTestSuite.SearchRequest("regex","CUSTOM",RuleDefinitionHistory.definition(rule),temporary.resolve("checkout").toString());
  var direct=new DirectRuleTestClient(new ProcessRunner(),true,temporary.resolve("tasks").toString()).search(request);
  assertEquals("COMPLETE",direct.status());assertFalse(direct.truncated());
  assertEquals(List.of(new RuleTestSuite.Location("Billing.txt",1),new RuleTestSuite.Location("src/app/Orders.txt",2)),direct.matches());
  assertEquals(direct.matches(),RuleTestSuiteRunner.search(request).matches(),"the subprocess and in-process entry points agree");
  rule.setRegexPattern("[");assertNotEquals("COMPLETE",RuleTestSuiteRunner.search(new RuleTestSuite.SearchRequest("regex","CUSTOM",RuleDefinitionHistory.definition(rule),temporary.resolve("checkout").toString())).status());
  assertThrows(IllegalArgumentException.class,()->RuleTestSuiteRunner.search(new RuleTestSuite.SearchRequest("regex","CUSTOM",RuleDefinitionHistory.definition(rule),temporary.resolve("missing").toString())));
 }
 @Test void opengrepReviewedTesterUsesPinnedAdapterAndReturnsUnsupportedOrFailedEvidence()throws Exception {
  org.junit.jupiter.api.Assumptions.assumeTrue(System.getenv("WATCHTOWER_OPENGREP_PATH")!=null,"Pinned binary required");
  var dto=new com.tracelink.appsec.module.opengrep.model.OpengrepCustomRuleDto();common(dto);dto.setEngineRuleId("reviewed.eval");dto.setLicense("MIT");dto.setSource("reviewed/fixture-v1");dto.setDefinition("{\"languages\":[\"python\"],\"pattern\":\"eval(...)\"}");
  var client=new DirectRuleTestClient(new ProcessRunner(),true,temporary.toString());
  var candidate=new com.tracelink.appsec.module.opengrep.model.OpengrepCustomRuleDto();common(candidate);candidate.setEngineRuleId(dto.getEngineRuleId());candidate.setLicense("MIT");candidate.setSource(dto.getSource());candidate.setDefinition("{\"languages\":[\"python\"],\"patterns\":[{\"pattern\":\"eval(...)\"}]}");
  var files=new ArrayList<RuleTestSuite.File>();for(int i=0;i<4;i++)files.add(new RuleTestSuite.File(UUID.randomUUID().toString(),"reviewed"+i+".py",i%2==0?"eval(user_input)\n":"safe = 1\n"));
  // Exercise the minimum four-fixture promotion collection within the unchanged outer deadline.
  var collection=new RuleTestSuite.Request("opengrep","CUSTOM",RuleDefinitionHistory.definition(dto),RuleDefinitionHistory.definition(candidate),files);
  var results=client.test(collection);assertEquals(4,results.cases().size());assertTrue(results.cases().stream().allMatch(p->p.base().complete()&&p.candidate().complete()));
  var pair=results.cases().getFirst();assertEquals(1,pair.base().matches().getFirst().line());assertTrue(results.cases().get(1).candidate().matches().isEmpty());
  assertFalse(RuleDefinitionHistory.encode(pair).contains("user_input"));
  var unsupported=RuleTestSuiteRunner.run(request(dto,dto,"reviewed.txt","private fixture body")).cases().getFirst();assertEquals("UNSUPPORTED",unsupported.base().status());
  dto.setDefinition("{\"languages\":[\"python\"],\"pattern\":\"eval(\"}");assertFalse(RuleTestSuiteRunner.run(request(dto,dto,"reviewed.py","clean = 1\n")).cases().getFirst().base().complete());
  try(var remaining=java.nio.file.Files.list(temporary)){assertEquals(0,remaining.count());}
 }
 @Test void jsonYamlAndPmdReuseTheirRealAdaptersAndKeepMalformedInputAsMissingEvidence() {
  var json=new JsonRuleDto();common(json);json.setFileExtension(".yaml");json.setQuery("$.people[*][?(@.age>45)]");
  var valid=RuleTestSuiteRunner.run(request(json,json,"people-v1.yaml","people:\n - age: 53\n - age: 23\n")).cases().getFirst();
  assertTrue(valid.base().complete());assertEquals(2,valid.base().matches().getFirst().line());
  var invalid=RuleTestSuiteRunner.run(request(json,json,"people-v1.yaml","people: [broken")).cases().getFirst();assertFalse(invalid.base().complete());
  var pmd=new PMDCustomRuleDto();common(pmd);pmd.setParserLanguage("java");pmd.setRuleClass("net.sourceforge.pmd.lang.rule.xpath.XPathRule");
  var property=new PMDPropertyDto();property.setName("xpath");property.setValue("//MethodDeclaration");pmd.setProperties(List.of(property));
  var parsed=RuleTestSuiteRunner.run(request(pmd,pmd,"Fixture.java","class Fixture { void unsafe() {} }")).cases().getFirst();assertTrue(parsed.base().complete());assertEquals(1,parsed.base().matches().size());
 }
}
