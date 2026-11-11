package com.tracelink.appsec.watchtower.core.rule.candidate;

import java.util.List;

/** Data-returning protocol shared by the application and the engine tester entry point. */
public final class RuleTestSuite {
 private RuleTestSuite() { }
 public record File(String id,String path,String content) { }
 // Labels/cohorts/review rationales are deliberately withheld from the executable engine.
 public record Request(String module,String designation,String baseDefinition,String candidateDefinition,
   List<File> files) { }
 public record Comparison(String fixtureId,RuleTestResult base,RuleTestResult candidate) { }
 public record Result(List<Comparison> cases) { }
 /** Variant search (R5.3): one exact definition over a pinned checkout. Only locations return. */
 public record SearchRequest(String module,String designation,String definition,String directory) { }
 public record Location(String path,int line) { }
 public record SearchResult(String status,List<Location> matches,int errors,boolean truncated,String identity) { }
 public static final int MAX_SEARCH_LOCATIONS=200;
}
