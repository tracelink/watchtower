package com.tracelink.appsec.watchtower.core.assistant.assessment;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.rule.knowledge.KnowledgeService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/** R6: evidence refusals, reply checks, caching, chat-budget charging, views and blind agreement. */
class FindingAssessmentTest {
 static final String VALID="{\"verdict\":\"LIKELY_FALSE_POSITIVE\",\"criteria\":{"
  +"\"input_reaches_sink\":{\"answer\":\"yes\",\"reason\":\"The request parameter reaches the write on line 88.\"},"
  +"\"sanitized\":{\"answer\":\"yes\",\"reason\":\"Encode.forHtml(name) on line 86 escapes it, per approved knowledge K-7.\"},"
  +"\"test_or_generated_code\":{\"answer\":\"no\",\"reason\":\"Production controller code.\"},"
  +"\"matches_rule_intent\":{\"answer\":\"yes\",\"reason\":\"The rule targets unescaped HTML output.\"}},\"cited_lines\":[81,86,88],\"knowledge_ids\":[\"K-7\"]}";

 @Test void repliesKeepOnlyPlainSentencesSuppliedLinesAndSuppliedKnowledge()throws Exception{
  var mapper=AssistantState.mapper();
  var ok=AssessmentText.accept(mapper.readTree(VALID),48,128,Set.of("K-7")).orElseThrow();
  assertEquals("LIKELY_FALSE_POSITIVE",ok.verdict());assertEquals(List.of(81,86,88),ok.citedLines());assertEquals("yes",ok.criteria().get("sanitized").get("answer"));
  for(String bad:List.of(VALID.replace("LIKELY_FALSE_POSITIVE","SUPPRESS"),VALID.replace("[81,86,88]","[81,86,300]"),VALID.replace("[\"K-7\"]","[\"K-9\"]"),
    VALID.replace("Production controller code.","String x = name; return x;"),VALID.replace("Production controller code.","token x9f2aQ7hLm3Zp0Vb8Nc4Rt"),
    VALID.replace("\"no\",","\"maybe\","),VALID.replace("}},\"cited","},\"extra\":{\"answer\":\"no\",\"reason\":\"abc\"}},\"cited")))
   assertTrue(AssessmentText.accept(mapper.readTree(bad),48,128,Set.of("K-7")).isEmpty(),bad);
  var schema=AssessmentText.schema();assertFalse(schema.path("additionalProperties").asBoolean(true));
  assertEquals(4,schema.path("properties").path("criteria").path("required").size());
 }

 // Bitbucket stores a pull request's commit abbreviated; the source control system completes it first
 @Test void anAbbreviatedCommitIsCompletedBeforeSourceIsReadAndIsRefusedPlainlyWhenItCannotBe()throws Exception{
  var rules=mock(RuleService.class);var entity=mock(RuleEntity.class);var dto=mock(RuleDto.class);var stewardship=new RuleStewardship();stewardship.setCwe("CWE-79");
  when(rules.getRule(7L)).thenReturn(entity);when(entity.toDto()).thenReturn(dto);when(dto.getId()).thenReturn(7L);when(dto.getStewardship()).thenReturn(stewardship);
  var secrets=mock(AssistantSecretFindings.class);var source=mock(AssistantSourceTools.class);var tools=mock(AssistantToolRegistry.class);var knowledge=mock(KnowledgeService.class);
  var records=mock(LedgerRepository.class);when(records.maps(anyString(),anyInt(),anyInt(),any(),any())).thenReturn(List.of());
  when(tools.ruleEvidence(dto)).thenReturn(Map.of("id",7L,"name","xss-output"));
  var repo=mock(RepositoryEntity.class);when(repo.getId()).thenReturn(42L);when(repo.getRepoName()).thenReturn("payments-api");
  var api=mock(com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi.class);
  when(source.target("alice",42L)).thenReturn(new AssistantSourceTools.Target(repo,api));
  var evidence=new AssessmentEvidence(mock(FindingLocator.class),source,secrets,tools,knowledge,rules,records);
  var located=new FindingLocator.Located("pull_request",5,"9","o".repeat(64),7L,"a".repeat(64),repo,"c".repeat(12),"src/OrderController.java",88,false,null);
  String full="c".repeat(40);
  when(api.fullCommit("payments-api","c".repeat(12))).thenReturn(full);
  when(source.window(eq("alice"),eq(repo),eq(full),anyString(),eq(88),eq(40))).thenReturn(new AssistantSourceTools.Window(88,List.of(Map.of("line",88,"text","out.write(name);")),false));
  var gathered=evidence.gather("alice",located);
  assertNull(gathered.refusal());assertEquals(full,gathered.located().commit());assertTrue(gathered.input().contains(full));
  when(api.fullCommit("payments-api","c".repeat(12))).thenThrow(new java.io.IOException("Commit unavailable"));
  var refused=evidence.gather("alice",located);
  assertTrue(refused.refusal().contains("could not be completed to a full hash"));
 }
 // Evidence gathering with collaborators replaced: the refusals happen before anything is sent.
 @Test void evidenceRefusesSecretsUploadsAndUnreadableSourceBeforeAnythingIsSent()throws Exception{
  var rules=mock(RuleService.class);var entity=mock(RuleEntity.class);var dto=mock(RuleDto.class);var stewardship=new RuleStewardship();stewardship.setCwe("CWE-79");
  when(rules.getRule(7L)).thenReturn(entity);when(entity.toDto()).thenReturn(dto);when(dto.getId()).thenReturn(7L);when(dto.getStewardship()).thenReturn(stewardship);
  var secrets=mock(AssistantSecretFindings.class);var source=mock(AssistantSourceTools.class);var tools=mock(AssistantToolRegistry.class);var knowledge=mock(KnowledgeService.class);
  var records=mock(LedgerRepository.class);when(records.maps(anyString(),anyInt(),anyInt(),any(),any())).thenReturn(List.of(Map.of("judgment","FALSE_POSITIVE","n",4L)));
  when(tools.ruleEvidence(dto)).thenReturn(Map.of("id",7L,"name","xss-output"));
  var repo=mock(RepositoryEntity.class);when(repo.getId()).thenReturn(42L);
  var evidence=new AssessmentEvidence(mock(FindingLocator.class),source,secrets,tools,knowledge,rules,records);
  var located=new FindingLocator.Located("pull_request",5,"9","o".repeat(64),7L,"a".repeat(64),repo,"c".repeat(40),"src/OrderController.java",88,false,null);
  assertEquals("Uploaded code is not kept",evidence.gather("alice",located.withUnavailable("Uploaded code is not kept")).refusal());
  assertTrue(evidence.gather("alice",new FindingLocator.Located("pull_request",5,"9","o".repeat(64),7L,null,repo,"c".repeat(40),"a.java",1,true,null)).refusal().contains("secrets"));
  when(secrets.isSecretRule(dto)).thenReturn(true);
  assertTrue(evidence.gather("alice",located).refusal().contains("never sent"));
  when(secrets.isSecretRule(dto)).thenReturn(false);
  when(source.window(eq("alice"),eq(repo),anyString(),anyString(),eq(88),eq(40))).thenThrow(new IllegalArgumentException("Source withheld: recorded secret findings could not be checked"));
  assertTrue(evidence.gather("alice",located).refusal().contains("could not be read or checked for secrets"));
  reset(source);
  when(source.window(eq("alice"),eq(repo),anyString(),anyString(),eq(88),eq(40))).thenReturn(new AssistantSourceTools.Window(87,List.of(Map.of("line",87,"text","x"),Map.of("line",88,"text","[REDACTED: secret detected by Betterleaks]")),true));
  assertTrue(evidence.gather("alice",located).refusal().contains("secret was recorded on this line"));
  reset(source);
  when(source.window(eq("alice"),eq(repo),anyString(),anyString(),eq(88),eq(40))).thenReturn(new AssistantSourceTools.Window(48,List.of(Map.of("line",48,"text","class OrderController {"),Map.of("line",88,"text","out.write(name);")),false));
  when(knowledge.applicable(7L,"CWE-79",42L,"java")).thenReturn(List.of(Map.of("id","K-7","statement","Encode.forHtml escapes HTML output")));
  var gathered=evidence.gather("alice",located);
  assertNull(gathered.refusal());assertEquals(48,gathered.firstLine());assertEquals(88,gathered.lastLine());assertEquals(Set.of("K-7"),gathered.knowledgeIds());
  assertTrue(gathered.input().contains("out.write(name);"));assertTrue(gathered.input().contains("xss-output"));
  assertTrue(gathered.input().contains("Fewer than 5 other findings"),"four other judgments could identify this one, so no counts are sent");
  verify(records).maps(contains("f.occurrenceKey<>?2"),anyInt(),anyInt(),eq(7L),eq("o".repeat(64)));
  when(records.maps(anyString(),anyInt(),anyInt(),any(),any())).thenReturn(List.of(Map.of("judgment","FALSE_POSITIVE","n",6L),Map.of("judgment","TRUE_POSITIVE","n",1L)));
  var counted=evidence.gather("alice",located);assertTrue(counted.input().contains("\"FALSE_POSITIVE\":6"));
  assertNull(AssessmentEvidence.language("Makefile"));assertEquals("python",AssessmentEvidence.language("a/b.PY"));
 }

 R1Database database;FindingAiExposures exposures;AssistantSettingsService settings;FindingAssessmentService service;AssessmentEvidence evidence;AssistantAccess access;
 final AtomicBoolean keyConfigured=new AtomicBoolean(true);final AtomicReference<Instant> now=new AtomicReference<>(Instant.parse("2026-10-14T09:00:00Z"));
 final List<OpenAiLlmClient.Structured> sent=new ArrayList<>();final Deque<Object> replies=new ArrayDeque<>();
 FindingLocator.Located located(String key){
  var repo=mock(RepositoryEntity.class);when(repo.getId()).thenReturn(42L);
  return new FindingLocator.Located("pull_request",5,key,FindingFeedbackService.occurrenceKey("pull_request",5,key),7L,"a".repeat(64),repo,"c".repeat(40),"src/OrderController.java",88,false,null);
 }
 @BeforeEach void setup()throws Exception{
  database=new R1Database();settings=database.service(new AssistantSettingsService(database.records,R1Database.keys(keyConfigured),null,false));
  configure(true,2_000_000);
  access=mock(AssistantAccess.class);evidence=mock(AssessmentEvidence.class);
  when(evidence.locate(eq("pull_request"),eq(5L),anyString())).thenAnswer(i->located(i.getArgument(2)));
  when(evidence.gather(anyString(),any())).thenAnswer(i->new AssessmentEvidence.Gathered(i.getArgument(1),null,"{\"code_window\":[]}",48,128,Set.of("K-7")));
  Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return now.get();}};
  FindingAssessmentService.Provider provider=request->{sent.add(request);Object next=replies.isEmpty()?reply(VALID):replies.poll();if(next instanceof java.io.IOException e)throw e;return (OpenAiLlmClient.StructuredReply)next;};
  var services=new FindingAssessmentService.Services(evidence,settings,R1Database.keys(keyConfigured),access,new AssistantBudgetService(database.records,database.tx));
  exposures=new FindingAiExposures(database.repository(FindingAiExposureRepository.class),database.tx,clock);
  service=new FindingAssessmentService(services,database.repository(FindingAssessmentRepository.class),database.repository(FindingAssessmentViewRepository.class),exposures,database.records,database.tx,provider,clock);
 }
 @AfterEach void close(){database.close();}
 static OpenAiLlmClient.StructuredReply reply(String text){return new OpenAiLlmClient.StructuredReply(text,false,"completed",3000,400,true);}
 void configure(boolean enabled,long userDailyCostMicros)throws Exception{
  var current=settings.get();var config=(ObjectNode)AssistantState.mapper().valueToTree(current.settings());
  config.put("defaultModel","fixture-model").put("defaultEffort","low").put("userDailyCostMicros",userDailyCostMicros);
  config.putArray("allowedModels").addObject().put("id","fixture-model").put("inputTokenLimit",65536).put("outputTokenLimit",8192).put("inputMicrosPerMillion",1000000).put("outputMicrosPerMillion",2000000)
   .put("validatedAt","2026-10-10").put("validationRef","fixture:responses-v1").putArray("efforts").add("low");
  config.putObject("findingAssessment").put("enabled",enabled);
  settings.save(new AssistantSettingsService.Versioned(current.version(),settings.decode(config.toString())),"admin");
 }
 long charged(){return database.jdbc.queryForObject("SELECT COALESCE(SUM(charged_cost_micros),0) FROM assistant_budget_daily",Long.class);}

 @Test void anAnswerIsStoredOnceChargedAtActualUsageAndRecordsWhoSawIt(){
  var first=service.assess("alice","pull_request",5,"9");
  assertEquals("ASSESSED",first.get("state"));assertEquals("LIKELY_FALSE_POSITIVE",first.get("verdict"));assertEquals(List.of(81,86,88),first.get("cited_lines"));
  assertEquals(1,sent.size());assertEquals("fixture-model",sent.getFirst().model());assertEquals("low",sent.getFirst().effort());
  assertEquals(2*(3000+800L),charged(),"user and organization buckets each settle to 3,000 in + 400 out at the model price");
  var again=service.assess("bob","pull_request",5,"9");assertEquals(first.get("id"),again.get("id"));assertEquals(1,sent.size(),"asking again returns the stored answer at no cost");
  assertEquals(2,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_assessment_views",Integer.class));
  service.latest("alice","pull_request",5,"9");assertEquals(2,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_assessment_views",Integer.class),"first view is kept once per person");
  assertEquals("NONE",service.latest("carol","pull_request",5,"10").get("state"));
 }
 @Test void refusalsAndRejectedRepliesNeverExposeAnythingAndRefusalsCostNothing(){
  when(evidence.gather(anyString(),argThat(l->l!=null&&"11".equals(l.findingKey())))).thenAnswer(i->AssessmentEvidence.Gathered.refused(i.getArgument(1),"This rule detects secrets. Findings of secret rules are never sent to the AI."));
  var refused=service.assess("alice","pull_request",5,"11");
  assertEquals("INSUFFICIENT_EVIDENCE",refused.get("state"));assertEquals(0,sent.size());assertEquals(0L,charged());
  replies.add(reply(VALID.replace("Production controller code.","String x = name;")));
  var rejected=service.assess("alice","pull_request",5,"12");
  assertEquals("REJECTED",rejected.get("state"));assertFalse(rejected.containsKey("criteria"));
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_assessments WHERE criteria_json LIKE '%String x%'",Integer.class));
  var retried=service.assess("alice","pull_request",5,"12");
  assertEquals(2,sent.size(),"asking again replaces a rejected answer");assertEquals("ASSESSED",retried.get("state"));
  assertEquals(1,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_assessments WHERE finding_key='12'",Integer.class));
 }
 @Test void switchesKeysBudgetsAndProviderErrorsAreExplained()throws Exception{
  configure(false,2_000_000);assertEquals("OFF",service.assess("alice","pull_request",5,"9").get("state"));
  configure(true,2_000_000);keyConfigured.set(false);assertEquals("NO_API_KEY",service.assess("alice","pull_request",5,"9").get("state"));
  keyConfigured.set(true);assertEquals(0,sent.size());
  configure(true,1000);
  assertEquals(429,assertThrows(ResponseStatusException.class,()->service.assess("alice","pull_request",5,"9")).getStatusCode().value());assertEquals(0,sent.size());
  verify(evidence,never()).gather(anyString(),any());
  configure(true,2_000_000);
  replies.add(new LlmClient.ProviderFailure("PROVIDER_RATE_LIMIT",true,0));
  assertEquals(503,assertThrows(ResponseStatusException.class,()->service.assess("alice","pull_request",5,"9")).getStatusCode().value());
  assertEquals(0L,charged(),"an error reply used nothing");
  replies.add(new LlmClient.ProviderFailure("PROVIDER_TRANSPORT",true,0));
  assertThrows(ResponseStatusException.class,()->service.assess("alice","pull_request",5,"9"));
  assertTrue(charged()>0,"a timed-out request may have been charged");
  doThrow(new org.springframework.security.access.AccessDeniedException("no")).when(access).require("mallory","Assistant Source Read");
  assertThrows(org.springframework.security.access.AccessDeniedException.class,()->service.assess("mallory","pull_request",5,"9"));
  assertThrows(IllegalArgumentException.class,()->{var c=(ObjectNode)AssistantState.mapper().valueToTree(settings.get().settings());c.put("defaultModel","");c.putObject("findingAssessment").put("enabled",true);settings.decode(c.toString());},
   "turning assessment on needs an allowed default model");
 }
 @Test void agreementCountsOnlyJudgmentsMadeWithoutSeeingTheAnswer(){
  // Finding 1: AI says false positive; alice judged false positive before anyone saw it -> blind, agrees.
  replies.add(reply(VALID));service.assess("bot","pull_request",5,"1");
  judge("1","FALSE_POSITIVE","alice",now.get().toEpochMilli()+1000);
  // Finding 2: AI says true positive; bob saw it, then judged false positive -> not blind.
  replies.add(reply(VALID.replace("LIKELY_FALSE_POSITIVE","LIKELY_TRUE_POSITIVE")));service.assess("bob","pull_request",5,"2");
  judge("2","FALSE_POSITIVE","bob",now.get().toEpochMilli()+1000);
  // Finding 3: AI says true positive; carol judged false positive without seeing it -> blind, disagrees.
  replies.add(reply(VALID.replace("LIKELY_FALSE_POSITIVE","LIKELY_TRUE_POSITIVE")));service.assess("bot","pull_request",5,"3");
  judge("3","FALSE_POSITIVE","carol",now.get().toEpochMilli()+1000);
  // Finding 4: needs review; finding 5: no human judgment.
  replies.add(reply(VALID.replace("LIKELY_FALSE_POSITIVE","NEEDS_REVIEW")));service.assess("bot","pull_request",5,"4");
  service.assess("bot","pull_request",5,"5");
  // An older answer for finding 1 from another model never counts twice.
  database.jdbc.update("INSERT INTO finding_assessments(assessment_id,occurrence_key,scan_type,scan_id,finding_key,rule_id,status,verdict,model,effort,prompt_version,input_tokens,output_tokens,cost_micros,requested_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,0,0,0,?,?)",
   UUID.randomUUID().toString(),FindingFeedbackService.occurrenceKey("pull_request",5,"1"),"pull_request",5,"1",7,"ASSESSED","LIKELY_TRUE_POSITIVE","older-model","low",AssessmentText.PROMPT_VERSION,"bot",1L);
  var a=service.agreement();
  assertEquals(2L,a.get("blind_cases"));assertEquals(1L,a.get("agreed"));assertEquals(0.5,a.get("agreement_rate"));
  assertEquals(1L,a.get("excluded_seen_before_judging"));assertEquals(1L,a.get("excluded_no_human_judgment"));assertEquals(1L,a.get("excluded_needs_review_or_insufficient"));
  @SuppressWarnings("unchecked") var matrix=(Map<String,Long>)a.get("matrix");
  assertEquals(Map.of("LIKELY_FALSE_POSITIVE|FALSE_POSITIVE",1L,"LIKELY_TRUE_POSITIVE|FALSE_POSITIVE",1L),matrix);
 }
 @Test void everyAssessmentViewRecordsOneExposurePerPersonAndFinding(){
  service.assess("alice","pull_request",5,"9");service.latest("alice","pull_request",5,"9");service.assess("bob","pull_request",5,"9");
  var key=FindingFeedbackService.occurrenceKey("pull_request",5,"9");
  assertEquals(2,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_ai_exposure WHERE occurrence_key=?",Integer.class,key));
  assertEquals("ASSESSMENT",database.jdbc.queryForObject("SELECT source FROM finding_ai_exposure WHERE occurrence_key=? AND viewer='alice'",String.class,key));
 }
 @Test void aRejectedAnswerIsNeverShownSoItRecordsNoExposure(){
  replies.add(reply(VALID.replace("Production controller code.","String x = name;")));
  assertEquals("REJECTED",service.assess("alice","pull_request",5,"12").get("state"));
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_ai_exposure",Integer.class));
 }
 @Test void agreementAlsoExcludesAChatOpinionSeenBeforeJudging(){
  // Finding 6: carol got a chat opinion about it, then judged: not blind even though she never opened the stored assessment.
  replies.add(reply(VALID.replace("LIKELY_FALSE_POSITIVE","LIKELY_TRUE_POSITIVE")));service.assess("bot","pull_request",5,"6");
  exposures.record(FindingFeedbackService.occurrenceKey("pull_request",5,"6"),"Carol",FindingAiExposures.CHAT);
  judge("6","FALSE_POSITIVE","carol",now.get().toEpochMilli()+1000);
  // Finding 7: dave's chat opinion came after his judgment, so his judgment still counts as blind.
  replies.add(reply(VALID));service.assess("bot","pull_request",5,"7");
  judge("7","FALSE_POSITIVE","dave",now.get().toEpochMilli()-1000);
  exposures.record(FindingFeedbackService.occurrenceKey("pull_request",5,"7"),"dave",FindingAiExposures.CHAT);
  var a=service.agreement();
  assertEquals(1L,a.get("blind_cases"));assertEquals(1L,a.get("agreed"));assertEquals(1L,a.get("excluded_seen_before_judging"));
 }
 void judge(String key,String judgment,String reviewer,long at){
  database.jdbc.update("INSERT INTO finding_feedback(occurrence_key,scan_type,scan_id,finding_key,rule_id,revision,occurred_at,judgment,disposition,explanation,reviewer,updated_at,version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)",
   FindingFeedbackService.occurrenceKey("pull_request",5,key),"pull_request",5,key,7,"a".repeat(64),at,judgment,"OTHER","checked",reviewer,at);
 }
}
