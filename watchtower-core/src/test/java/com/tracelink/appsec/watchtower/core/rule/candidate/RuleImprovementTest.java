package com.tracelink.appsec.watchtower.core.rule.candidate;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import java.nio.file.Path;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.web.server.ResponseStatusException;
import com.fasterxml.jackson.databind.node.*;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.rule.improvement.*;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;

/** Complete fake-provider evidence → proposal → edited candidate journey over JPA and worker checkpoints. */
class RuleImprovementTest {
 @TempDir Path transcript;R1Database d;AssistantSettingsService settings;AssistantPersistence db;AssistantAccess access;
 RuleCandidateService candidates;RuleCandidateTester tester;RuleCandidateContractTest.TestEntity active;
 RuleImprovementEvidence evidence;RuleImprovementService improvements;AssistantToolRegistry tools;AssistantBudgetService budgets;
 @BeforeEach void setup()throws Exception {
  d=new R1Database();access=mock(AssistantAccess.class);when(access.authorities(anyString())).thenReturn(Set.of("Assistant Use","Ruleset View","Rule Modify","Scan Results View"));
  settings=d.service(new AssistantSettingsService(d.records,R1Database.keys(new java.util.concurrent.atomic.AtomicBoolean(true)),null,false));
  var cfg=(ObjectNode)AssistantState.mapper().valueToTree(settings.get().settings());cfg.put("enabled",true).put("defaultModel","fixture-model").put("defaultEffort","low");
  cfg.putArray("allowedModels").addObject().put("id","fixture-model").put("inputTokenLimit",65536).put("outputTokenLimit",8192).put("inputMicrosPerMillion",1000000).put("outputMicrosPerMillion",2000000).put("validatedAt","2026-10-10").put("validationRef","fixture:responses-v1").putArray("efforts").add("low");settings.save(new AssistantSettingsService.Versioned(1,settings.decode(cfg.toString())),"admin");
  db=d.service(new AssistantPersistence(d.records,d.tx,new LocalAssistantTranscriptStore(transcript),settings,access,e->{}));budgets=d.service(new AssistantBudgetService(d.records,d.tx));
  active=RuleCandidateContractTest.entity("unsafe|risky");d.seedRule(1,active.toDto().getRevision());var rules=mock(RuleRepository.class);when(rules.findById(1L)).thenAnswer(i->Optional.of(active));
  tester=mock(RuleCandidateTester.class);candidates=d.service(new RuleCandidateService(d.records,rules,mock(RuleService.class),d.service(new RuleDefinitionHistory(d.records)),tester,""));
  var knowledge=mock(com.tracelink.appsec.watchtower.core.rule.knowledge.KnowledgeService.class);when(knowledge.applicable(any(),any(),any(),any())).thenReturn(List.of());
  evidence=d.service(new RuleImprovementEvidence(d.records,candidates,access,new AssistantSecretFindings(mock(RuleService.class),mock(com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService.class),d.records,mock(com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository.class),mock(com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService.class)),d.service(new RuleHealthService(d.records,6,3,.5)),knowledge));
  improvements=d.service(new RuleImprovementService(d.records,evidence,db,candidates,access,settings));
  // A person's decision on one finding: proposals are refused without human evidence.
  long seeded=System.currentTimeMillis();d.records.insert(new FindingFeedbackEntity("seed-review","pull_request",3L,"seed",1L,active.toDto().getRevision(),true,seeded,"FALSE_POSITIVE","TEST_CODE","Human explanation","human",seeded,1L));tools=new AssistantToolRegistry(access,mock(RuleService.class),mock(com.tracelink.appsec.watchtower.core.ruleset.RulesetService.class),mock(RuleHealthService.class),mock(RuleReviewService.class),d.records,mock(AssistantSourceTools.class),mock(AssistantSecretFindings.class));
 }
 @AfterEach void close(){d.close();}
 Map<String,Object> generate()throws Exception {return improvements.generate(1,new RuleImprovementService.Generate(UUID.randomUUID().toString(),90,List.of(),"Reduce noisy unsafe alternative",""),"alice");}
 String answer(String outcome,String citations,String changes){return "{\"outcome\":\""+outcome+"\",\"problem\":\"Investigate this matching behavior\",\"citations\":"+citations+",\"changes\":"+changes+",\"expectedBenefit\":\"Narrow noisy alternative\",\"regressions\":[\"May miss unsafe\"],\"limitations\":[\"Examples are illustrative, not executed\"],\"examples\":[\"ILLUSTRATIVE_TRANSCRIPT_ONLY\"],\"proposedTests\":[\"Review positive and clean cases before testing\"]}";}
 void run(Map<String,Object> generated,String output)throws Exception {
  var turn=db.claim((String)generated.get("turnId"),UUID.randomUUID().toString()).orElseThrow();
  LlmClient client=request->{assertTrue(request.tools().isEmpty());assertEquals("improvement-v1",request.promptVersion());ArrayNode items=AssistantState.mapper().createArrayNode();items.addObject().put("type","message").putArray("content").addObject().put("type","output_text").put("text",output);return new LlmClient.Response(items,"completed",100,100,true);};
  var runner=new AssistantTurnRunner(db,settings,tools,client,budgets);runner.setImprovements(improvements);runner.run(turn);
 }
 @Test void workerValidatesProposalAndHumanEditsAreSavedWithDurablePrivateProvenance()throws Exception {
  var generated=generate();String id=(String)generated.get("id");run(generated,answer("PROPOSED_CHANGE","[\"rule/1\"]","{\"regexPattern\":\"risky\"}"));
  var result=improvements.get(1,id,"alice");assertEquals("READY",result.get("status"));assertEquals("COMPLETED",result.get("turnStatus"));
  assertFalse(d.jdbc.queryForObject("SELECT proposal_json FROM rule_improvement_proposals",String.class).contains("ILLUSTRATIVE_TRANSCRIPT_ONLY"));assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM rule_candidates",Integer.class));
  var save=new RuleImprovementService.Save(((Number)result.get("version")).longValue(),active.toDto().getRevision(),Map.of("regexPattern","risky|reviewed"),"Human accepted and edited the pattern",null);
  var saved=improvements.save(1,id,save,"alice");assertEquals(saved,improvements.save(1,id,save,"alice"));
  assertEquals(1,d.jdbc.queryForObject("SELECT COUNT(*) FROM rule_candidates",Integer.class));assertTrue(d.jdbc.queryForObject("SELECT accepted_patch_json FROM rule_candidate_provenance",String.class).contains("risky|reviewed"));
  assertThrows(ResponseStatusException.class,()->improvements.get(1,id,"bob"));assertEquals("unsafe|risky",active.pattern);verify(tester,never()).test(any());
 }
 @Test void inventedCitationsUnsupportedFieldsAndMalformedOutputNeverCreateCandidates()throws Exception {
  for(String output:List.of(answer("PROPOSED_CHANGE","[\"invented/7\"]","{\"regexPattern\":\"risky\"}"),answer("PROPOSED_CHANGE","[\"rule/1\"]","{\"priority\":\"LOW\"}"),"not JSON",answer("PROPOSED_CHANGE","[\"rule/1\"]","{\"message\":\"only prose\"}"))){var generated=generate();run(generated,output);assertEquals("INVALID_OUTPUT",improvements.get(1,(String)generated.get("id"),"alice").get("status"));}
  assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM rule_candidates",Integer.class));verify(tester,never()).test(any());
 }
 @Test void staleProposalsAndRevokedGrantsCannotSaveCandidates()throws Exception {
  var generated=generate();String id=(String)generated.get("id");run(generated,answer("PROPOSED_CHANGE","[\"rule/1\"]","{\"regexPattern\":\"risky\"}"));var result=improvements.get(1,id,"alice");var save=new RuleImprovementService.Save(((Number)result.get("version")).longValue(),active.toDto().getRevision(),Map.of("regexPattern","risky"),"Reviewed",null);
  active.pattern="concurrent";assertTrue((Boolean)improvements.get(1,id,"alice").get("stale"));assertThrows(ResponseStatusException.class,()->improvements.save(1,id,save,"alice"));
  active.pattern="unsafe|risky";doThrow(new org.springframework.security.access.AccessDeniedException("revoked")).when(access).require("alice","Rule Modify");assertThrows(org.springframework.security.access.AccessDeniedException.class,()->improvements.save(1,id,save,"alice"));assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM rule_candidates",Integer.class));
 }
 @Test void evidenceMixesJudgmentsAndSeparatesRiskHistoryAndHoldout()throws Exception {
  long now=System.currentTimeMillis();String revision=active.toDto().getRevision();
  for(String judgment:List.of("TRUE_POSITIVE","FALSE_POSITIVE","UNKNOWN"))for(int n=0;n<6;n++)d.records.insert(new FindingFeedbackEntity(judgment+n,"pull_request",1L,"key"+n,1L,revision,true,now,judgment,"ACCEPTED_RISK","Human explanation","human",now+n,1L));
  d.records.insert(new FindingFeedbackEntity("historical","pull_request",2L,"old",1L,null,false,now,"FALSE_POSITIVE","TEST_CODE","Historical evidence","human",now,1L));
  d.records.insert(new RuleEvaluationFixtureEntity(UUID.randomUUID().toString(),1L,"HIDDEN_HOLDOUT_REFERENCE","a".repeat(64),"NO_MATCH","HOLDOUT","human","reviewed/example",now));
  var manifest=evidence.gather(1,90,"","alice");assertEquals(4,manifest.references().stream().filter(r->r.id().startsWith("feedback/TRUE_POSITIVE")).count());assertTrue(manifest.samples().stream().anyMatch(s->s.truncated()));
  String json=RuleDefinitionHistory.encode(manifest);assertTrue(json.contains("ACCEPTED_RISK"));assertTrue(json.contains("HISTORICAL_OR_UNKNOWN"));assertFalse(json.contains("HIDDEN_HOLDOUT_REFERENCE"));
  var generated=generate();var state=db.state(db.turn((String)generated.get("turnId")));assertFalse(state.protocol.toString().contains("HIDDEN_HOLDOUT_REFERENCE"));
 }
 @Test void canceledAndChatOffRequestsNeverCallProvider()throws Exception {
  var generated=generate();db.cancel((String)generated.get("turnId"),"alice");assertTrue(db.claim((String)generated.get("turnId"),"worker").isEmpty());
  var cfg=(ObjectNode)AssistantState.mapper().valueToTree(settings.get().settings());cfg.put("enabled",false);settings.save(new AssistantSettingsService.Versioned(settings.get().version(),settings.decode(cfg.toString())),"admin");assertThrows(ResponseStatusException.class,this::generate);
 }
 @Test void crossEngineSecretFeedbackAndQuestionAreWithheldAndAdviceCannotCreateCandidate()throws Exception {
  active.getStewardship().setCwe("CWE-798");long now=System.currentTimeMillis();d.records.insert(new FindingFeedbackEntity("secret-feedback","pull_request",1L,"secret",1L,active.toDto().getRevision(),true,now,"TRUE_POSITIVE","ACTION_REQUIRED","private pasted value","human",now,1L));
  var manifest=evidence.gather(1,90,"","alice");assertFalse(RuleDefinitionHistory.encode(manifest).contains("private pasted value"));
  var generated=improvements.generate(1,new RuleImprovementService.Generate(UUID.randomUUID().toString(),90,List.of("feedback/secret-feedback"),"private engineer pasted value",""),"alice");assertFalse(db.state(db.turn((String)generated.get("turnId"))).protocol.toString().contains("private engineer pasted value"));
  run(generated,answer("ADVICE_ONLY","[\"rule/1\"]","{}"));var result=improvements.get(1,(String)generated.get("id"),"alice");assertEquals("READY",result.get("status"));assertThrows(IllegalArgumentException.class,()->improvements.save(1,(String)generated.get("id"),new RuleImprovementService.Save(((Number)result.get("version")).longValue(),active.toDto().getRevision(),Map.of("regexPattern","risky"),"Advice only",null),"alice"));
 }
 @Test void generatingWithoutReviewedFindingsIsRefusedBeforeAnyTask()throws Exception {
  d.jdbc.update("DELETE FROM finding_feedback");
  var manifest=evidence.gather(1,90,"","alice");assertFalse(RuleImprovementEvidence.hasHumanEvidence(manifest));
  var refused=assertThrows(IllegalArgumentException.class,this::generate);assertEquals(RuleImprovementService.NO_EVIDENCE,refused.getMessage());
  assertEquals(0,d.jdbc.queryForObject("SELECT COUNT(*) FROM rule_improvement_proposals",Integer.class));
 }
 @Test void evidenceSplitsThisVersionFromOlderForEveryKind()throws Exception {
  long now=System.currentTimeMillis();String revision=active.toDto().getRevision();
  d.records.insert(new FindingFeedbackEntity("older-review","pull_request",4L,"older",1L,null,false,now,"FALSE_POSITIVE","TEST_CODE","Older","human",now,1L));
  d.records.insert(new RuleReviewItemEntity("review-current",1L,revision,"alice","OPEN","Noisy","Narrow it",null,null,null,null,"",now,now,0L));
  d.records.insert(new RuleReviewItemEntity("review-older",1L,"b".repeat(64),"alice","OPEN","Noisy","Narrow it",null,null,null,null,"",now,now,0L));
  var samples=evidence.gather(1,90,"","alice").samples();
  var currentFp=samples.stream().filter(s->s.kind().equals("FALSE_POSITIVE")&&s.revisionScope().equals("CURRENT")).findFirst().orElseThrow();
  var olderFp=samples.stream().filter(s->s.kind().equals("FALSE_POSITIVE")&&s.revisionScope().equals("HISTORICAL_OR_UNKNOWN")).findFirst().orElseThrow();
  var reviews=samples.stream().filter(s->s.kind().equals("SAVED_REVIEWS")).findFirst().orElseThrow();
  assertEquals(1,currentFp.total());assertEquals(1,currentFp.currentTotal());assertEquals(1,olderFp.total());assertEquals(0,olderFp.currentTotal());
  assertEquals(2,reviews.total());assertEquals(1,reviews.currentTotal());
 }
 @Test void historyReplayRequiresCurrentScanEvidenceGrants()throws Exception {
  var generated=generate();var snapshot=db.state(db.turn((String)generated.get("turnId")));
  doThrow(new org.springframework.security.access.AccessDeniedException("revoked")).when(access).require("alice","Scan Results View");
  assertThrows(org.springframework.security.access.AccessDeniedException.class,()->tools.replay("alice",snapshot));
  assertThrows(org.springframework.security.access.AccessDeniedException.class,()->tools.auditReplay("alice",snapshot));
 }
}
