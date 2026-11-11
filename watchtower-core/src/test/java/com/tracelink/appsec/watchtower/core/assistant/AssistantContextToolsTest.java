package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import com.tracelink.appsec.watchtower.core.assistant.assessment.*;
import com.tracelink.appsec.watchtower.core.assistant.context.*;
import com.tracelink.appsec.watchtower.core.assistant.tools.ContextTools;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/** S1: the read tools return what the person could read on the page, a secret only as a marker, and write nothing. */
class AssistantContextToolsTest {
 static final Set<String> GRANTS=Set.of("Assistant Use","Scan Results View","Ruleset View","Repository Settings View","Assistant Source Read");
 @TempDir Path dir;AssistantFixture fx;FindingLocator locator;AssistantSecretFindings secrets;FindingAssessmentService assessments;List<AssistantTool> tools;RuleDto rule;RepositoryEntity repo;
 @BeforeEach @SuppressWarnings("unchecked") void setup()throws Exception{
  fx=new AssistantFixture(dir,GRANTS);fx.tools.setSettings(fx.settings);
  fx.configure(c->{c.putObject("features").putObject("enabled").put("contextCards",true);c.putObject("findingAssessment").put("enabled",true);});
  locator=mock(FindingLocator.class);secrets=mock(AssistantSecretFindings.class);assessments=mock(FindingAssessmentService.class);
  repo=mock(RepositoryEntity.class);when(repo.getRepoName()).thenReturn("payments-api");
  var entity=mock(RuleEntity.class);rule=mock(RuleDto.class);when(fx.rules.getRule(7L)).thenReturn(entity);when(entity.toDto()).thenReturn(rule);
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(),Set.of("generic-api-key"),Set.of("betterleaks")));
  var located=new FindingLocator.Located("pull_request",5,"9","o".repeat(64),7L,"a".repeat(64),repo,"c".repeat(40),"src/OrderController.java",88,false,null);
  when(locator.locateDetailed("pull_request",5,"9")).thenReturn(new FindingLocator.Detail(located,"xss-output","PMD","HIGH","Unescaped output","Payments API"));
  var findings=new FindingContextProvider(locator,fx.rules,secrets,fx.database.records,fx.database.repository(FindingAssessmentRepository.class));
  var summaries=new ScanSummaries(fx.database.records,mock(RepoScanRepository.class),mock(RepoScanReportService.class),secrets);
  ObjectProvider<FindingAssessmentService> provider=mock(ObjectProvider.class);when(provider.getObject()).thenReturn(assessments);
  var set=new ContextTools(findings,new RepositoryContextProvider(fx.database.repository(RepositoryRepository.class)),new PullRequestContextProvider(summaries),summaries,provider);
  tools=set.tools();tools.forEach(fx.tools::register);
 }
 @AfterEach void close(){fx.close();}
 JsonNode call(String name,String args){return fx.tools.invoke("alice",name,args,16384,AssistantState.TOOL_VERSION,"turn-1").path("data");}
 static final String FINDING="{\"finding_key\":\"9\",\"scan_id\":5,\"scan_type\":\"pull_request\"}";

 @Test void allFiveToolsAreReadsBehindTheirSwitch(){
  assertEquals(Set.of("get_finding","get_finding_assessment","get_repository","get_pull_request","get_scan_summary"),new TreeSet<>(tools.stream().map(AssistantTool::name).toList()));
  for(var t:tools){
   assertEquals(AssistantTool.Effect.EVIDENCE_READ,t.effect(),t.name());
   assertEquals("get_finding_assessment".equals(t.name())?AssistantFeature.FINDING_ASSESSMENT:AssistantFeature.CONTEXT_CARDS,t.feature(),t.name());
  }
  assertTrue(fx.tools.schemas("alice").toString().contains("\"get_finding\""));
 }
 @Test void theAssessmentToolFollowsTheFindingAssessmentSwitchAndTheOthersFollowPageContext()throws Exception{
  assertTrue(fx.tools.schemas("alice").toString().contains("\"get_finding_assessment\""));
  fx.configure(c->{c.putObject("features").putObject("enabled").put("contextCards",true);c.putObject("findingAssessment").put("enabled",false);});
  var offered=fx.tools.schemas("alice").toString();
  assertFalse(offered.contains("\"get_finding_assessment\""),"switched off, the tool is not offered");assertTrue(offered.contains("\"get_finding\""),"the other page tools are unaffected");
  assertThrows(IllegalArgumentException.class,()->call("get_finding_assessment",FINDING),"and a call from an older chat is refused");
  fx.configure(c->{c.putObject("features").putObject("enabled").put("contextCards",false);c.putObject("findingAssessment").put("enabled",true);});
  assertTrue(fx.tools.schemas("alice").toString().contains("\"get_finding_assessment\""),"it does not depend on the page context switch");
  assertFalse(fx.tools.schemas("alice").toString().contains("\"get_finding\""));
 }
 @Test void theToolsAreOffUntilTheSwitchIsOnAndStopWhenItIsTurnedOff()throws Exception{
  fx.configure(c->c.putObject("features").putObject("enabled").put("contextCards",false));
  assertFalse(fx.tools.schemas("alice").toString().contains("\"get_finding\""));
  assertThrows(IllegalArgumentException.class,()->call("get_finding",FINDING));
 }
 @Test void aFindingComesBackAsFactsAndASecretOnlyAsTheMarker(){
  var data=call("get_finding",FINDING);
  assertEquals("HIGH",data.path("severity").asText());assertEquals("src/OrderController.java",data.path("path").asText());assertTrue(data.has("message_untrusted"));
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(7L),Set.of(),Set.of()));
  var blocked=call("get_finding",FINDING);
  assertEquals("{\"blocked\":\"secret finding\"}",blocked.toString(),"no path, line, rule or reason");
  verifyNoInteractions(assessments);
  assertEquals("{\"blocked\":\"secret finding\"}",call("get_finding_assessment",FINDING).toString(),"the stored assessment of a now-secret finding is not read");
  verifyNoInteractions(assessments);
 }
 @Test void aStoredAssessmentIsLabelledAsAdvice(){
  when(assessments.latest("alice","pull_request",5,"9")).thenReturn(Map.of("state","ASSESSED","verdict","LIKELY_FALSE_POSITIVE"));
  var data=call("get_finding_assessment",FINDING);
  assertEquals("LIKELY_FALSE_POSITIVE",data.path("verdict").asText());assertTrue(data.path("label").asText().startsWith("AI advice"));
  verify(assessments).latest("alice","pull_request",5,"9");
 }
 @Test void assessmentsNeedTheSameGrantsAsReadingThemOnTheFindingPage(){
  var needs=tools.stream().filter(t->t.name().equals("get_finding_assessment")).findFirst().orElseThrow().authorities();
  assertEquals(AssistantSourceTools.GRANTS,needs);
 }
 @Test void aForgedOrUnknownIdIsRejectedWithoutDetail(){
  when(locator.locateDetailed("pull_request",5,"404")).thenThrow(new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND));
  assertThrows(IllegalArgumentException.class,()->call("get_finding","{\"finding_key\":\"404\",\"scan_id\":5,\"scan_type\":\"pull_request\"}"));
  assertThrows(IllegalArgumentException.class,()->call("get_repository","{\"repo_id\":999}"));
  assertThrows(IllegalArgumentException.class,()->call("get_pull_request","{\"scan_id\":999}"));
  assertThrows(IllegalArgumentException.class,()->call("get_finding","{\"finding_key\":\"9\",\"scan_id\":0,\"scan_type\":\"pull_request\"}"),"ids are positive");
  assertThrows(IllegalArgumentException.class,()->call("get_finding","{\"finding_key\":\"9\",\"scan_id\":5,\"scan_type\":\"pull_request\",\"extra\":1}"),"strict schema");
 }
 @Test void aScanSummaryCountsSecretsWithoutNamingThemAndShowsNotNeededScannersAsFinished(){
  var jdbc=fx.database.jdbc;fx.database.seedPr(1,1);
  jdbc.update("UPDATE pull_request_container SET api_label='Bitbucket',repo_name='Payments API',pr_id='42',closed_state=NULL WHERE container_id=1");
  var snapshot=new CodeScanExecutionSnapshot(CodeScanExecutionSnapshot.SCHEMA,1L,"default",null,List.of(),List.of(
    new CodeScanExecutionSnapshot.EngineExecution("PMD",null,"RAN"),new CodeScanExecutionSnapshot.EngineExecution("Checkov",null,"NOT_APPLICABLE"),new CodeScanExecutionSnapshot.EngineExecution("ESLint",null,"FAILED")),null);
  jdbc.update("UPDATE pull_request_scans SET execution_snapshot_json=? WHERE scan_entity_id=1",CodeScanExecutionSnapshotCodec.encode(snapshot));
  var scan=fx.database.records.find(PullRequestScanEntity.class,1L);
  for(var row:List.of(List.of(1,"xss-output","PMD"),List.of(1,"xss-output","PMD"),List.of(1,"naming","PMD"),List.of(1,"generic-api-key","Betterleaks")))
   new org.springframework.transaction.support.TransactionTemplate(fx.database.tx).executeWithoutResult(status->{
    var v=new PullRequestViolationEntity();v.setScan(scan);v.setViolationName((String)row.get(1));v.setFileName("src/A.java");v.setLineNum(1);
    v.setRuleIdentity(new RuleExecutionIdentity(null,(String)row.get(2),"a".repeat(64),null,null));fx.database.records.insert(v);
   });
  var summary=call("get_scan_summary","{\"scan_id\":1,\"scan_type\":\"pull_request\"}");
  assertEquals(3,summary.path("findings_by_severity").path("UNKNOWN").asInt(),"three non-secret findings; severity is grouped, and a missing one is unknown");
  assertEquals(1,summary.path("secret_findings").asInt());assertFalse(summary.toString().contains("generic-api-key"),"a secret rule is counted, never named");
  assertEquals(4,summary.path("total_findings").asInt(),"the total is given, so the secret finding is not lost from a sum of the severities");
  assertTrue(summary.path("total_findings_note").asText().contains("secret"),"and it says what the total contains");
  assertEquals(2,summary.path("top_rules").path("xss-output").asInt());
  var engines=summary.path("engines");
  assertEquals(1,engines.path("ran").asInt());assertEquals(1,engines.path("not_needed").asInt(),"no matching files is finished, not skipped");
  assertEquals("failed",engines.path("not_finished").path("ESLint").asText());assertFalse(engines.path("not_finished").has("Checkov"));
  var pr=call("get_pull_request","{\"scan_id\":1}");
  assertEquals("Payments API",pr.path("repository").asText());assertFalse(pr.has("top_rules"),"the card carries counts only");assertEquals(1,pr.path("secret_findings").asInt());
 }
 @Test @SuppressWarnings("unchecked") void aBrokenRecordIsReportedAsNotAvailableInsteadOfFailingTheTurn(){
  var broken=mock(PullRequestContextProvider.class);when(broken.resolve(any())).thenThrow(new NullPointerException("corrupt snapshot"));
  var set=new ContextTools(new FindingContextProvider(locator,fx.rules,secrets,fx.database.records,fx.database.repository(FindingAssessmentRepository.class)),mock(RepositoryContextProvider.class),broken,mock(ScanSummaries.class),mock(ObjectProvider.class));
  var pr=set.tools().stream().filter(t->t.name().equals("get_pull_request")).findFirst().orElseThrow();
  var e=assertThrows(IllegalArgumentException.class,()->pr.invoke("alice",AssistantState.mapper().createObjectNode().put("scan_id",1)));
  assertEquals("Not available",e.getMessage());
  var revoked=mock(PullRequestContextProvider.class);when(revoked.resolve(any())).thenThrow(new org.springframework.security.access.AccessDeniedException("no"));
  var again=new ContextTools(new FindingContextProvider(locator,fx.rules,secrets,fx.database.records,fx.database.repository(FindingAssessmentRepository.class)),mock(RepositoryContextProvider.class),revoked,mock(ScanSummaries.class),mock(ObjectProvider.class));
  assertThrows(org.springframework.security.access.AccessDeniedException.class,()->again.tools().stream().filter(t->t.name().equals("get_pull_request")).findFirst().orElseThrow().invoke("alice",AssistantState.mapper().createObjectNode().put("scan_id",1)),"a revoked grant still stops the turn");
 }
 @Test void aRepositoryAndARuleBuildCardsFromTheirIds()throws Exception{
  fx.database.jdbc.update("INSERT INTO repositories(repo_entity_id,api_label,repo_name,scan_type,last_review_date,scanning_paused,configuration_version,criticality,enabled) VALUES (3,'Bitbucket','payments-api','SCM',0,FALSE,0,2,TRUE)");
  var data=call("get_repository","{\"repo_id\":3}");
  assertEquals("payments-api",data.path("name").asText());assertEquals(false,data.path("scanning_paused").asBoolean(true));
  when(rule.getName()).thenReturn("xss-output");when(rule.getModule()).thenReturn("PMD");when(rule.getId()).thenReturn(7L);
  var card=new RuleContextProvider(fx.rules).resolve(new ContextRequest.Ids(null,null,null,null,7L));
  assertEquals("Rule · xss-output",card.title());assertEquals("PMD",card.facts().get("engine"));
  assertEquals(ContextCard.UNAVAILABLE,new RuleContextProvider(fx.rules).resolve(new ContextRequest.Ids(null,null,null,null,99L)).state());
 }
}
