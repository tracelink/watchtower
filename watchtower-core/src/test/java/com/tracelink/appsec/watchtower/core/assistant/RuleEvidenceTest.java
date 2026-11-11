package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.transaction.support.TransactionTemplate;
import com.tracelink.appsec.watchtower.core.metrics.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.feedback.*;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;

class RuleEvidenceTest {
 R1Database d;FindingFeedbackService feedback;RuleMetricWriter metrics;RuleHealthService health;final String revision="a".repeat(64);
 @BeforeEach void setup(){d=new R1Database();feedback=d.service(new FindingFeedbackService(d.records,mock(RepoScanRepository.class),mock(RepoScanReportService.class)));metrics=d.service(new RuleMetricWriter(d.records));health=d.service(new RuleHealthService(d.records,6,3,.5));d.seedRule(1,revision);d.seedPr(1,System.currentTimeMillis());for(long i=1;i<=5;i++)d.jdbc.update("INSERT INTO pull_request_violations(vio_entity_id,scan_entity_id,execution_rule_id,rule_revision,effective_blocking,line_number) VALUES (?,1,1,?,TRUE,1)",i,revision);}
 FindingFeedbackService.Update update(List<String> keys,FindingFeedbackService.Judgment judgment,FindingFeedbackService.Disposition disposition,Map<String,Long> versions){return new FindingFeedbackService.Update("pull_request",1,keys,judgment,disposition,"short human rationale",versions);}
 @AfterEach void close(){d.close();}
 @Test void mixedFiveFindingPRSeparatesCorrectnessFromAcceptedRisk(){
  metrics.record("pull_request",1,System.currentTimeMillis(),null,Collections.nCopies(5,new RuleMetricWriter.Count(new RuleExecutionIdentity(1L,"regex",revision,null,null),true)));
  feedback.save(update(List.of("1","2"),FindingFeedbackService.Judgment.FALSE_POSITIVE,FindingFeedbackService.Disposition.OTHER,Map.of()),"alice");feedback.save(update(List.of("3","4","5"),FindingFeedbackService.Judgment.TRUE_POSITIVE,FindingFeedbackService.Disposition.ACCEPTED_RISK,Map.of()),"alice");
  var h=health.health(1,revision,90,"pull_request");assertEquals(2L,((Number)h.get("fp")).longValue());assertEquals(3L,((Number)h.get("tp")).longValue());assertEquals(.4,h.get("reviewed_fp_rate"));assertEquals(0L,h.get("bypass_events"));assertFalse(((List<?>)h.get("chips")).contains("Needs review"));
  feedback.save(update(List.of("1"),FindingFeedbackService.Judgment.UNKNOWN,FindingFeedbackService.Disposition.OTHER,Map.of("1",1L)),"bob");h=health.health(1,revision,90,"pull_request");assertEquals(.25,h.get("reviewed_fp_rate"));assertEquals(2,feedback.audit("pull_request",1,"1").size());assertThrows(org.springframework.web.server.ResponseStatusException.class,()->feedback.save(update(List.of("1"),FindingFeedbackService.Judgment.TRUE_POSITIVE,FindingFeedbackService.Disposition.OTHER,Map.of("1",1L)),"charlie"));
 }
 @Test void individualOccurrenceKeysAreDistinctAndLegacyIdentityStaysUnknown(){
  assertNotEquals(FindingFeedbackService.occurrenceKey("pull_request",1,"1"),FindingFeedbackService.occurrenceKey("pull_request",1,"2"));d.jdbc.update("UPDATE pull_request_violations SET execution_rule_id=NULL,rule_revision=NULL,effective_blocking=NULL WHERE vio_entity_id=1");feedback.save(update(List.of("1"),FindingFeedbackService.Judgment.FALSE_POSITIVE,FindingFeedbackService.Disposition.OTHER,Map.of()),"alice");var row=d.jdbc.queryForMap("SELECT * FROM finding_feedback");assertNull(row.get("rule_id"));assertNull(row.get("revision"));assertNull(row.get("effective_blocking"));assertNull(health.health(1,revision,30,"all").get("reviewed_fp_rate"));
 }
 @Test void idempotentCountsIncludeUnknownCoverageAndSkipReportReuse(){
  var identity=new RuleExecutionIdentity(1L,"regex",revision,null,null);var snapshot=new CodeScanExecutionSnapshot(1,1L,"selected",RulePriority.HIGH,List.of(new CodeScanExecutionSnapshot.SelectedRule(identity,"name",RulePriority.INFORMATIONAL,RuleState.ACTIVE,"scanner","UNKNOWN",null)),List.of(new CodeScanExecutionSnapshot.EngineExecution("scanner",EngineExecutionIdentity.unknown("scanner"),"FAILED")),null);
  metrics.record("upload",4,System.currentTimeMillis(),snapshot,List.of(new RuleMetricWriter.Count(identity,null)));metrics.record("upload",4,System.currentTimeMillis(),snapshot,List.of(new RuleMetricWriter.Count(identity,null)));metrics.record("upload",5,System.currentTimeMillis(),snapshot.reusedFrom(4),List.of(new RuleMetricWriter.Count(identity,null)));
  var h=health.health(1,revision,30,"upload");assertEquals(1L,((Number)h.get("findings")).longValue());assertEquals(1L,((Number)h.get("failed_scans")).longValue());assertEquals(1L,((Number)h.get("blocking_unknown")).longValue());assertNull(h.get("known_opportunities"));assertNull(h.get("reviewed_fp_rate"));
 }
 @Test void aScannerWithNoMatchingFilesNeverCountsAsASuccessfulZeroMatchRun(){
  var identity=new RuleExecutionIdentity(1L,"regex",revision,null,null);
  var snapshot=new CodeScanExecutionSnapshot(1,1L,"selected",RulePriority.HIGH,List.of(new CodeScanExecutionSnapshot.SelectedRule(identity,"name",RulePriority.INFORMATIONAL,RuleState.ACTIVE,"scanner","NOT_APPLICABLE",null)),List.of(new CodeScanExecutionSnapshot.EngineExecution("scanner",EngineExecutionIdentity.unknown("scanner"),"NOT_APPLICABLE")),null);
  metrics.record("upload",6,System.currentTimeMillis(),snapshot,List.of());
  assertEquals("NOT_APPLICABLE",d.jdbc.queryForObject("SELECT engine_status FROM rule_metric_scan WHERE scan_id=6",String.class));
  assertEquals("NOT_APPLICABLE",d.jdbc.queryForObject("SELECT coverage FROM rule_metric_scan WHERE scan_id=6",String.class));
  var h=health.health(1,revision,30,"upload");
  assertNotEquals("SUCCESSFUL_ENGINE_ZERO_MATCHES",h.get("evidence_state"),"an engine with nothing to scan has not shown the rule finds nothing");
 }
 @Test void bulkFailureRollsBackAllJudgmentsAndAudit(){
  var tx=new TransactionTemplate(d.tx);assertThrows(RuntimeException.class,()->tx.executeWithoutResult(s->feedback.save(update(List.of("1","999"),FindingFeedbackService.Judgment.FALSE_POSITIVE,FindingFeedbackService.Disposition.OTHER,Map.of()),"alice")));assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback",Integer.class));assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback_audit",Integer.class));
 }
 @Test void healthFiltersPoliciesAndExcludesLabelsOutsideExecutedScope(){
  var identity=new RuleExecutionIdentity(1L,"regex",revision,null,null);
  d.jdbc.update("UPDATE pull_request_violations SET effective_blocking=FALSE WHERE vio_entity_id=2");
  metrics.record("pull_request",1,System.currentTimeMillis(),null,List.of(new RuleMetricWriter.Count(identity,true),new RuleMetricWriter.Count(identity,false)));
  feedback.save(update(List.of("1"),FindingFeedbackService.Judgment.FALSE_POSITIVE,FindingFeedbackService.Disposition.OTHER,Map.of()),"alice");
  feedback.save(update(List.of("2"),FindingFeedbackService.Judgment.TRUE_POSITIVE,FindingFeedbackService.Disposition.ACCEPTED_RISK,Map.of()),"alice");
  var blocking=health.health(1,revision,30,"pull_request","blocking");assertEquals(1L,blocking.get("findings"));assertEquals(1.0,blocking.get("reviewed_fp_rate"));assertNull(blocking.get("known_opportunities"));
  assertEquals(0.0,health.health(1,revision,30,"pull_request","nonblocking").get("reviewed_fp_rate"));
  d.jdbc.update("DELETE FROM rule_metric_scan WHERE scan_id=1");assertNull(health.health(1,revision,30,"pull_request").get("reviewed_fp_rate"));assertEquals(2L,health.health(1,revision,30,"pull_request").get("excluded_reviews"));
 }
 @Test void reviewTransitionsAndCaseReferencesDoNotChangeEnforcement()throws Exception{
  var rules=mock(RuleService.class);var entity=mock(RuleEntity.class);var dto=mock(RuleDto.class);when(rules.getCurrentRule(1)).thenReturn(entity);when(entity.toDto()).thenReturn(dto);when(dto.getRevision()).thenReturn(revision);var reviews=d.service(new RuleReviewService(d.records,rules));
  var id=reviews.save(new RuleReviewService.Review(null,1,revision,"alice",RuleReviewService.Status.OPEN,"confirmed FP","narrow matcher","finding","1",null,null,"",0),"alice");assertEquals(1,reviews.list(1,0).size());reviews.save(new RuleReviewService.Review(id,1,revision,"alice",RuleReviewService.Status.ACCEPTED,"confirmed FP","narrow matcher",null,null,null,null,"reviewed recommendation",1),"bob");assertEquals(2,reviews.audit(id).size());assertThrows(org.springframework.web.server.ResponseStatusException.class,()->reviews.save(new RuleReviewService.Review(id,1,revision,"alice",RuleReviewService.Status.CLOSED,"review","",null,null,null,null,"",1),"bob"));
  assertNotNull(reviews.intake(new RuleReviewService.Case(1,revision,"FALSE_POSITIVE","fixtures/regex/clean-v1.json","b".repeat(64),"NO_MATCH","regex","java"),"alice"));assertThrows(IllegalArgumentException.class,()->reviews.intake(new RuleReviewService.Case(1,revision,"FALSE_POSITIVE","../../source.java","b".repeat(64),"NO_MATCH","regex","java"),"alice"));assertEquals(revision,d.jdbc.queryForObject("SELECT rule_revision FROM rules WHERE rule_id=1",String.class));
 }
}
