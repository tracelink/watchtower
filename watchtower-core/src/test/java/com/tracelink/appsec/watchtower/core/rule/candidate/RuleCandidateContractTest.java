package com.tracelink.appsec.watchtower.core.rule.candidate;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.transaction.support.TransactionTemplate;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.rule.*;

class RuleCandidateContractTest {
 @TempDir Path assets;R1Database d;RuleRepository repository;RuleService cache;RuleDefinitionHistory history;
 RuleCandidateTester tester;RuleCandidateService service;TestEntity active;
 @BeforeEach void setup()throws Exception {
  d=new R1Database();

  d.seedRule(1,"a".repeat(64));
  repository=mock(RuleRepository.class);cache=mock(RuleService.class);history=d.service(new RuleDefinitionHistory(d.records));
  tester=mock(RuleCandidateTester.class);when(tester.available()).thenReturn(true);when(tester.identity()).thenReturn("b".repeat(64));
  active=entity("unsafe|risky");when(repository.findById(1L)).thenAnswer(i->Optional.of(active));
  when(repository.saveAndFlush(any())).thenAnswer(i->{active=i.getArgument(0);return active;});
  service=d.service(new RuleCandidateService(d.records,repository,cache,history,tester,assets.toString()));
  when(tester.test(any())).thenAnswer(i->{
   RuleTestSuite.Request request=i.getArgument(0);var rows=new ArrayList<RuleTestSuite.Comparison>();
   for(var file:request.files()) {
    boolean old=file.content().contains("unsafe")||file.content().contains("risky"),next=file.content().contains("risky");
    rows.add(new RuleTestSuite.Comparison(file.id(),result(file,old),result(file,next)));
   }return new RuleTestSuite.Result(rows);
  });
 }
 static TestEntity entity(String pattern){var e=new TestEntity();e.setId(1);e.setName("same logical name");e.setPriority(RulePriority.HIGH);e.setAuthor("engineer");e.setMessage("Finding");e.setExternalUrl("https://example.test/rule");e.pattern=pattern;return e;}
 RuleTestResult result(RuleTestSuite.File file,boolean matched){return new RuleTestResult("COMPLETE","regex","recorded direct runtime",matched?List.of(new RuleTestResult.Match(file.path(),1,"c".repeat(64))):List.of(),0,1,"Fixture engine contract");}
 @AfterEach void close(){d.close();}
 String draft(){return service.create(new RuleCandidateService.Draft(1,active.toDto().getRevision(),RuleDefinitionHistory.JSON.createObjectNode().put("regexPattern","risky"),"Remove confirmed noisy alternative",null),"alice");}
 void fixtures()throws Exception {
  for(String cohort:List.of("REGRESSION","HOLDOUT"))for(String expected:List.of("MATCH","NO_MATCH")) {
   String reference=cohort.toLowerCase()+"-"+expected.toLowerCase()+"-v1.txt",body=expected.equals("MATCH")?"reviewed risky case "+cohort:"reviewed unsafe clean case "+cohort;
   Files.writeString(assets.resolve(reference),body);
   service.fixture(new RuleCandidateService.Fixture(1,reference,RuleDefinitionHistory.hash(body),expected,cohort,"reviewed/report-v1"),"reviewer");
  }
 }
 String passed(String id){String run=service.prepareRun(id,"alice");service.run(run,()->{});assertEquals("PASSED",service.runs(id).getFirst().get("status"));return run;}
 RuleCandidateService.Action action(String id,String run){var c=service.candidate(id);return new RuleCandidateService.Action(((Number)c.get("version")).longValue(),(String)c.get("revision"),run,run==null?null:(String)service.runs(id).stream().filter(r->run.equals(r.get("run_id"))).findFirst().orElseThrow().get("evidence_hash"),"Reviewed exact behavior and evidence");}
 @Test void reviewedWorkflowKeepsDraftSeparateAndBindsPromotionRollbackAndImmutableHistory()throws Exception {
  fixtures();String original=active.toDto().getRevision(),id=draft();history.record(active.toDto());assertEquals(1,history.list(1,0).size());assertEquals(original,active.toDto().getRevision());
  assertThrows(RuntimeException.class,()->service.transition(id,"PROMOTE",action(id,null),"alice"));
  String run=passed(id);var evidence=(String)service.runs(id).getFirst().get("evidence_json");assertTrue(evidence.contains("newlyMissed"));assertFalse(evidence.contains("reviewed risky case"));
  service.transition(id,"SHADOW",action(id,run),"alice");assertEquals(original,active.toDto().getRevision());
  var approval=action(id,run);new TransactionTemplate(d.tx).executeWithoutResult(tx->service.transition(id,"PROMOTE",approval,"alice"));
  assertEquals("risky",active.pattern);assertEquals(2,history.list(1,0).size());verify(cache).invalidateRuleCache();
  assertThrows(RuntimeException.class,()->service.transition(id,"PROMOTE",approval,"bob"));
  active.setPriority(RulePriority.LOW);active.getStewardship().setOwner("new owner");
  service.transition(id,"ROLLBACK",action(id,run),"bob");assertEquals("unsafe|risky",active.pattern);assertEquals(RulePriority.LOW,active.getPriority());assertEquals("new owner",active.getStewardship().getOwner());
  assertEquals(4,service.audit(id).size());assertEquals("ROLLED_BACK",service.candidate(id).get("status"));
 }
 @Test void changedDefinitionsFixturesAndExecutionProfilesCannotReusePassingApproval()throws Exception {
  fixtures();String id=draft(),run=passed(id);service.transition(id,"SHADOW",action(id,run),"alice");
  Files.writeString(assets.resolve("regression-match-v1.txt"),"changed asset");assertThrows(RuntimeException.class,()->service.transition(id,"PROMOTE",action(id,run),"alice"));
  Files.writeString(assets.resolve("regression-match-v1.txt"),"reviewed risky case REGRESSION");when(tester.identity()).thenReturn("d".repeat(64));
  assertThrows(RuntimeException.class,()->service.transition(id,"PROMOTE",action(id,run),"alice"));when(tester.identity()).thenReturn("b".repeat(64));
  active.pattern="other revision";assertThrows(RuntimeException.class,()->service.transition(id,"PROMOTE",action(id,run),"alice"));
  assertEquals("SHADOW",service.candidate(id).get("status"));verify(repository,never()).saveAndFlush(any());
 }
 @Test void shadowSamplesAreSeparateIdempotentAndStopWhenApproverAccessIsRevoked()throws Exception {
  fixtures();String id=draft(),run=passed(id);service.transition(id,"SHADOW",action(id,run),"alice");
  var access=mock(com.tracelink.appsec.watchtower.core.assistant.AssistantAccess.class);
  var shadow=d.service(new RuleShadowService(d.records,tester,access,d.tx));
  var ruleset=new com.tracelink.appsec.watchtower.core.ruleset.RulesetDto();ruleset.setRules(Set.of(active.toDto()));
  var config=new com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig();config.setRuleset(ruleset);config.setWorkingDirectory(assets);
  clearInvocations(tester);shadow.compare("pull_request",21,config);shadow.compare("pull_request",21,config);
  verify(tester,times(1)).test(any());assertEquals(1,shadow.observations(id,30).size());
  var evidence=(String)shadow.observations(id,30).getFirst().get("evidence_json");
  assertTrue(evidence.contains("normalEnforcementChanged"));assertFalse(evidence.contains("reviewed risky case"));
  assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback",Integer.class));
  assertEquals("unsafe|risky",active.pattern);
  doThrow(new org.springframework.security.access.AccessDeniedException("revoked")).when(access).require("alice","Assistant Source Read");
  clearInvocations(tester);shadow.compare("pull_request",22,config);verify(tester,never()).test(any());
  assertEquals("FAILED",d.jdbc.queryForObject("SELECT status FROM rule_shadow_observations WHERE scan_id=22",String.class));
  when(tester.moduleUnavailable(anyString())).thenReturn(true);
  clearInvocations(tester,access);shadow.compare("pull_request",23,config);
  verify(tester,never()).test(any());verifyNoInteractions(access);
  assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM rule_shadow_observations WHERE scan_id=23",Integer.class));
 }
 @Test void authoredFieldsAreBoundedAndHumanFixtureLabelsRemainIndependent()throws Exception {
  String original=active.toDto().getRevision();
  assertThrows(IllegalArgumentException.class,()->service.create(new RuleCandidateService.Draft(1,original,RuleDefinitionHistory.JSON.createObjectNode().put("priority","LOW"),"arbitrary enforcement change",null),"alice"));
  assertThrows(IllegalArgumentException.class,()->service.create(new RuleCandidateService.Draft(1,original,RuleDefinitionHistory.JSON.createObjectNode().put("regexPattern","unsafe|risky"),"no behavior change",null),"alice"));
  assertThrows(IllegalArgumentException.class,()->service.fixture(new RuleCandidateService.Fixture(1,"../source.java","a".repeat(64),"MATCH","REGRESSION","human/report"),"alice"));
  fixtures();String id=draft(),run=passed(id);
  Files.writeString(assets.resolve("additional-v1.txt"),"risky");service.fixture(new RuleCandidateService.Fixture(1,"additional-v1.txt",RuleDefinitionHistory.hash("risky"),"MATCH","HOLDOUT","human/report-v2"),"bob");
  assertThrows(RuntimeException.class,()->service.transition(id,"SHADOW",action(id,run),"alice"));
  assertEquals(original,active.toDto().getRevision());assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback",Integer.class));
 }
 @Test void replayFencesStaleWorkersAndRevokedRequestsWithoutPublishingOrChangingEnforcement()throws Exception {
  fixtures();String id=draft(),run=service.prepareRun(id,"alice");
  assertThrows(org.springframework.web.server.ResponseStatusException.class,()->service.prepareRun(id,"bob"));
  doAnswer(i->{d.jdbc.update("UPDATE rule_candidate_runs SET claim_token=? WHERE run_id=?",UUID.randomUUID().toString(),run);return new RuleTestSuite.Result(List.of());}).when(tester).test(any());
  service.run(run,()->{});assertEquals("RUNNING",service.runs(id).getFirst().get("status"));
  d.jdbc.update("UPDATE rule_candidate_runs SET lease_until=0 WHERE run_id=?",run);
  assertThrows(IllegalStateException.class,()->service.run(run,()->{throw new org.springframework.security.access.AccessDeniedException("revoked");}));
  assertEquals("FAILED",service.runs(id).getFirst().get("status"));assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM rule_candidate_runs WHERE active_candidate IS NOT NULL",Integer.class));
  String abandoned=service.prepareRun(id,"alice");
  d.jdbc.update("UPDATE rule_candidate_runs SET created_at=0 WHERE run_id=?",abandoned);
  d.jdbc.update("INSERT INTO async_jobs(job_type,payload,status) VALUES ('RULE_CANDIDATE_TEST',?,'QUEUED')",abandoned);
  when(tester.available()).thenReturn(false);service.reconcileRuns();
  assertEquals("QUEUED",d.jdbc.queryForObject("SELECT status FROM rule_candidate_runs WHERE run_id=?",String.class,abandoned));
  d.jdbc.update("UPDATE async_jobs SET status='FAILED'");service.reconcileRuns();
  assertEquals("FAILED",d.jdbc.queryForObject("SELECT status FROM rule_candidate_runs WHERE run_id=?",String.class,abandoned));
  when(tester.available()).thenReturn(true);String fresh=service.prepareRun(id,"alice");service.reconcileRuns();
  assertEquals("QUEUED",d.jdbc.queryForObject("SELECT status FROM rule_candidate_runs WHERE run_id=?",String.class,fresh));
  verify(repository,never()).saveAndFlush(any());
 }
 @Test void testerProtocolRejectsOmittedFixturesUnsupportedOutputAndUnboundedLocations() {
  String id=UUID.randomUUID().toString();var file=new RuleTestSuite.File(id,"fixture.txt","clean");var request=new RuleTestSuite.Request("regex","CUSTOM","{}","{}",List.of(file));
  assertThrows(IllegalArgumentException.class,()->RuleCandidateTester.validate(request,new RuleTestSuite.Result(List.of())));
  var invalid=new RuleTestResult("COMPLETE","regex","direct",List.of(new RuleTestResult.Match("../source",1,"a".repeat(64))),0,1,"");
  assertThrows(IllegalArgumentException.class,()->RuleCandidateTester.validate(request,new RuleTestSuite.Result(List.of(new RuleTestSuite.Comparison(id,invalid,invalid)))));
  var valid=result(file,false);RuleCandidateTester.validate(request,new RuleTestSuite.Result(List.of(new RuleTestSuite.Comparison(id,valid,valid))));
  var clients=mock(org.springframework.beans.factory.ObjectProvider.class);var client=mock(RuleTestClient.class);
  when(clients.getIfUnique()).thenReturn(client);when(client.executionIdentity()).thenReturn("b".repeat(64));
  var actual=new RuleCandidateTester(clients);var runtime=mock(RuleRuntimeAvailability.class);
  when(runtime.module()).thenReturn("Opengrep");when(runtime.available()).thenReturn(true);when(runtime.executionIdentity()).thenReturn("c".repeat(64));
  org.springframework.test.util.ReflectionTestUtils.setField(actual,"runtimes",List.of(runtime));String profile=actual.identity();
  when(runtime.executionIdentity()).thenReturn("d".repeat(64));assertNotEquals(profile,actual.identity());
  when(runtime.available()).thenReturn(false);assertTrue(actual.moduleUnavailable("opengrep"));assertThrows(IllegalStateException.class,()->actual.requireRuntime("opengrep"));
 }
 @Test void exampleHandoffRequiresConfirmationCurrentRevisionAndVerifiedAsset()throws Exception {
  String id=UUID.randomUUID().toString(),revision=active.toDto().getRevision();
  d.records.insert(new com.tracelink.appsec.watchtower.core.persistence.RuleRegressionCaseEntity(id,1L,revision,"FALSE_POSITIVE","example.txt",RuleDefinitionHistory.hash("clean"),"NO_MATCH","regex","text","reviewer",1L));
  assertFalse(service.preparation(1).suiteUsable());
  assertThrows(IllegalArgumentException.class,()->service.prepareRun(draft(),"alice"));
  assertThrows(IllegalArgumentException.class,()->service.registerCase(new RuleCandidateService.CaseFixture(1,revision,id,"NO_MATCH","REGRESSION",false),"alice"));
  assertThrows(IllegalArgumentException.class,()->service.registerCase(new RuleCandidateService.CaseFixture(1,revision,id,"NO_MATCH","REGRESSION",true),"alice"));
  Files.writeString(assets.resolve("example.txt"),"wrong");
  assertThrows(IllegalArgumentException.class,()->service.registerCase(new RuleCandidateService.CaseFixture(1,revision,id,"NO_MATCH","REGRESSION",true),"alice"));
  assertTrue(service.fixtures(1).isEmpty());
  Files.writeString(assets.resolve("example.txt"),"clean");
  var request=new RuleCandidateService.CaseFixture(1,revision,id,"NO_MATCH","REGRESSION",true);
  String fixture=service.registerCase(request,"alice");assertEquals(fixture,service.registerCase(request,"alice"));assertEquals(1,service.fixtures(1).size());
  assertFalse(service.preparation(1).suiteUsable());
  active.pattern="changed";assertThrows(org.springframework.web.server.ResponseStatusException.class,()->service.registerCase(request,"alice"));
  verify(tester,never()).test(any());
 }
 public static class TestDto extends CustomRuleDto {
  private String regexPattern;
  private String fileExtension="";
  public String getFileExtension(){return fileExtension;}public void setFileExtension(String value){fileExtension=value;}
  public String getRegexPattern(){return regexPattern;}public void setRegexPattern(String pattern){regexPattern=pattern;}
  @Override @JsonIgnore public String getModule(){return "regex";}
  @Override protected RuleRevision executableDefinition(){return newDefinition().field("pattern",regexPattern);}
  @Override public TestEntity toEntity(){var e=entity(regexPattern);e.setName(getName());e.setPriority(getPriority());return e;}
 }
 public static class TestEntity extends RuleEntity {
  String pattern;
  @Override public TestDto toDto(){var d=new TestDto();d.setId(getId());d.setName(getName());d.setPriority(getPriority());d.setAuthor(getAuthor());d.setMessage(getMessage());d.setExternalUrl(getExternalUrl());d.setRegexPattern(pattern);return withStewardship(d);}
 }
}
