package com.tracelink.appsec.watchtower.core.rule.candidate;

import java.util.List;

/** No source text, secrets or raw engine messages may cross the tester result boundary. */
public record RuleTestResult(String status,String engine,String runtime,List<Match> matches,
  int errors,long elapsedMillis,String limitation) {
 public record Match(String path,int line,String messageKey) { }
 public static RuleTestResult failed(String status,String engine,String runtime,String limitation) {
  return new RuleTestResult(status,engine,runtime,List.of(),1,0,limitation);
 }
 public boolean complete() { return "COMPLETE".equals(status)&&errors==0; }
}
