package com.tracelink.appsec.watchtower.core.rule.candidate;

import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/** Authorization-independent tester boundary; engines execute through the configured client.
 * No adapter means unavailable. Candidates are never invoked in the application JVM.
 */
@Component
public class RuleCandidateTester {
 @org.springframework.beans.factory.annotation.Autowired(required=false)
 private com.tracelink.appsec.watchtower.core.module.ModuleControlService controls;
 @org.springframework.beans.factory.annotation.Autowired(required=false)
 private List<RuleRuntimeAvailability> runtimes=List.of();
 public boolean moduleUnavailable(String module){return controls!=null&&!controls.enabled(module)
  ||runtimes.stream().filter(r->r.module().equalsIgnoreCase(module)).anyMatch(r->!r.available());}
 public void requireRuntime(String module){requireEnabled(module);if(moduleUnavailable(module))throw new IllegalStateException("Pinned module runtime unavailable");}
 public void requireEnabled(String module){if(controls!=null)controls.requireEnabled(module);}
 private final ObjectProvider<RuleTestClient> clients;
 public RuleCandidateTester(ObjectProvider<RuleTestClient> clients) { this.clients=clients; }
 public boolean available() {
  var client=clients.getIfUnique();return client!=null&&client.available()
    &&client.executionIdentity()!=null&&client.executionIdentity().matches("[a-f0-9]{64}");
 }
 public String identity() {
  var client=clients.getIfUnique();String profile=client==null?"unconfigured":client.executionIdentity();
  if(controls!=null)profile=RuleDefinitionHistory.hash(profile+"/"+controls.fingerprint());
  if(!runtimes.isEmpty())profile=com.tracelink.appsec.watchtower.core.rule.RuleRevision.definition("reviewed-runtime","v1")
   .field("profile",profile).unordered("modules",runtimes.stream().map(r->r.module()+"/"+r.executionIdentity()).toList()).hash();
  return profile;
 }
 /** Variant search (R5.3): same runtime/module gates as tests; only bounded locations return. */
 public RuleTestSuite.SearchResult search(RuleTestSuite.SearchRequest request) {
  requireRuntime(request.module());
  if(!available())throw new IllegalStateException("The rule test runner is disabled or unavailable");
  var result=clients.getIfUnique().search(request);requireRuntime(request.module());
  if(result==null||result.matches()==null||result.matches().size()>RuleTestSuite.MAX_SEARCH_LOCATIONS
    ||result.matches().stream().anyMatch(m->m.line()<1||!relative(m.path())))
   throw new IllegalStateException("Engine returned an unavailable location");
  return result;
 }
 /** A forward-slash relative path whose segments never leave the checkout; names like a..b.js are fine. */
 public static boolean relative(String path){
  if(path==null||path.isEmpty()||path.length()>1024||path.startsWith("/")||path.contains("\\")||path.matches("^[A-Za-z]:.*"))return false;
  return java.util.Arrays.stream(path.split("/")).noneMatch(s->s.isEmpty()||s.equals(".")||s.equals(".."));
 }
 public RuleTestSuite.Result test(RuleTestSuite.Request request) {
  requireRuntime(request.module());
  if(!available())throw new IllegalStateException("The rule test runner is disabled or unavailable");
  if(request.files()==null||request.files().isEmpty()||request.files().size()>20
    ||RuleDefinitionHistory.encode(request).getBytes(java.nio.charset.StandardCharsets.UTF_8).length>2*1024*1024)
   throw new IllegalArgumentException("Use 1–20 reviewed fixtures and at most 2 MiB of input");
  String identity=identity();var result=clients.getIfUnique().test(request);
  if(!available()||!identity.equals(identity()))throw new IllegalStateException("Rule test execution profile changed");
  requireRuntime(request.module());validate(request,result);return result;
 }
 static void validate(RuleTestSuite.Request request,RuleTestSuite.Result result) {
  if(result==null||result.cases()==null||result.cases().size()!=request.files().size()
    ||!result.cases().stream().map(RuleTestSuite.Comparison::fixtureId).sorted().toList()
       .equals(request.files().stream().map(RuleTestSuite.File::id).sorted().toList()))
   throw new IllegalArgumentException("Incomplete tester response");
  for(var pair:result.cases())for(var r:List.of(pair.base(),pair.candidate())) {
   if(r.matches()==null||r.matches().size()>200||r.errors()<0||r.elapsedMillis()<0
     ||r.runtime()==null||r.runtime().length()>16384||r.limitation()==null||r.limitation().length()>1000
     ||!request.module().equalsIgnoreCase(r.engine())
     ||!List.of("COMPLETE","FAILED","UNSUPPORTED","TIMEOUT","LIMIT").contains(r.status()))
    throw new IllegalArgumentException("Invalid tester evidence");
   var fixture=request.files().stream().filter(f->f.id().equals(pair.fixtureId())).findFirst().orElseThrow();
   for(var m:r.matches())if(!fixture.path().equals(m.path())||m.line()<1||m.line()>100000
     ||m.messageKey()==null||!m.messageKey().matches("[a-f0-9]{64}"))throw new IllegalArgumentException("Invalid match location");
  }
 }
}
