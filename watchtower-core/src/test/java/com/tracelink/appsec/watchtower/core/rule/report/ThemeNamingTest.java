package com.tracelink.appsec.watchtower.core.rule.report;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import com.tracelink.appsec.watchtower.core.assistant.*;

/** R5.2b: what leaves for naming, what is accepted back, the cache, the weekly budget and the states. */
class ThemeNamingTest {
 static final String VALID="{\"name\":\"Fires on generated test fixtures\",\"cause\":\"TEST_OR_GENERATED_CODE\",\"explanation\":\"Most records say the match is dummy data in generated test clients.\"}";

 @Test void recordTextLosesSecretsAddressesPathsAndTokenLikeWordsAndIsBounded(){
  String text=ThemeNamingText.redact("Mail alice@example.com, see https://wiki.example.com/x?a=1 and /src/gen/Client.java; token ghp_AbCdEf1234567890abcdef1234 build42x is fake, plain words stay.");
  assertFalse(text.contains("alice"));assertFalse(text.contains("wiki"));assertFalse(text.contains("Client.java"));assertFalse(text.contains("ghp_"));assertFalse(text.contains("build42x"));
  assertTrue(text.contains("plain words stay."));assertTrue(text.contains(ThemeNamingText.REDACTED));
  assertEquals(ThemeNamingText.MAX_RECORD_CHARS,ThemeNamingText.redact("word ".repeat(200)).length());
  assertEquals("",ThemeNamingText.redact(null));
 }
 @Test void repliesAreAcceptedOnlyAsPlainWordsWithAKnownCause()throws Exception{
  var mapper=AssistantState.mapper();
  var ok=ThemeNamingText.accept(mapper.readTree(VALID)).orElseThrow();
  assertEquals("TEST_OR_GENERATED_CODE",ok.cause());assertEquals("Fires on generated test fixtures",ok.name());
  for(String bad:List.of(
    VALID.replace("TEST_OR_GENERATED_CODE","SUPPRESS_RULE"),
    VALID.replace("Fires on generated test fixtures","Fires in src/gen/Client.java"),
    VALID.replace("dummy data","the value AKIA1234567890ABCDEF"),
    VALID.replace("Fires on generated test fixtures","x".repeat(61)),
    VALID.replace("Most records say","<b>Most</b> records say"),
    VALID.replace("}",",\"extra\":\"x\"}"),
    "{\"name\":\"Ok name\",\"cause\":\"UNCLEAR\"}"))
   assertTrue(ThemeNamingText.accept(mapper.readTree(bad)).isEmpty(),bad);
  var schema=ThemeNamingText.schema();assertFalse(schema.path("additionalProperties").asBoolean(true));
  assertEquals(ThemeNamingText.CAUSES.size(),schema.path("properties").path("cause").path("enum").size());
 }

 R1Database database;AssistantSettingsService settings;ThemeNamingService naming;AssistantSecretFindings secrets;
 final AtomicBoolean keyConfigured=new AtomicBoolean(true);final AtomicReference<Instant> now=new AtomicReference<>(Instant.parse("2026-10-14T09:00:00Z"));
 final List<OpenAiLlmClient.Structured> sent=new ArrayList<>();final Deque<Object> replies=new ArrayDeque<>();

 @BeforeEach void setup()throws Exception{
  database=new R1Database();settings=database.service(new AssistantSettingsService(database.records,R1Database.keys(keyConfigured),null,false));
  configure(true,30000);
  secrets=mock(AssistantSecretFindings.class);
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(8L),Set.of(),Set.of("betterleaks")));
  when(secrets.bypassesCoveringSecrets(any(),any())).thenReturn(Set.of());
  Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return now.get();}};
  ThemeNamingService.Provider provider=request->{
   sent.add(request);Object next=replies.isEmpty()?reply(VALID):replies.poll();
   if(next instanceof java.io.IOException e)throw e;return (OpenAiLlmClient.StructuredReply)next;
  };
  naming=new ThemeNamingService(database.repository(RuleReviewReportRepository.class),database.repository(ThemeNameRepository.class),settings,R1Database.keys(keyConfigured),secrets,database.records,database.tx,provider,clock);
  seedReport();
 }
 @AfterEach void close(){database.close();}
 static OpenAiLlmClient.StructuredReply reply(String text){return new OpenAiLlmClient.StructuredReply(text,false,"completed",1000,100,true);}
 void configure(boolean enabled,long weeklyMicros)throws Exception{
  var current=settings.get();var config=(ObjectNode)AssistantState.mapper().valueToTree(current.settings());
  config.putArray("allowedModels").addObject().put("id","fixture-model").put("inputTokenLimit",65536).put("outputTokenLimit",8192).put("inputMicrosPerMillion",1000000).put("outputMicrosPerMillion",2000000)
   .put("validatedAt","2026-10-10").put("validationRef","fixture:responses-v1").putArray("efforts").add("low");
  config.putObject("themeNaming").put("enabled",enabled).put("model","fixture-model").put("effort","low").put("weeklyCostMicros",weeklyMicros);
  settings.save(new AssistantSettingsService.Versioned(current.version(),settings.decode(config.toString())),"admin");
 }
 /** Three themes: feedback on rule 7, bypasses on secret rule 8, review decisions on rule 9. */
 void seedReport()throws Exception{
  long at=now.get().toEpochMilli();List<FeedbackThemes.Signal> signals=new ArrayList<>();
  for(int i=0;i<4;i++){
   String key="o".repeat(63)+i;signals.add(new FeedbackThemes.Signal(7,"finding_feedback","TEST_CODE",key,"alice",at-i,null));
   database.jdbc.update("INSERT INTO finding_feedback(occurrence_key,scan_type,scan_id,finding_key,rule_id,revision,occurred_at,judgment,disposition,explanation,reviewer,updated_at,version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)",
    key,"pull_request",i,"k"+i,7,"a".repeat(64),at,"FALSE_POSITIVE","TEST_CODE","Generated test fixture; ask alice@example.com, see /src/gen/Client.java",i<2?"alice":"bob",at);
  }
  for(int i=0;i<3;i++)signals.add(new FeedbackThemes.Signal(8,"bypass","TEST_CODE",Integer.toString(500+i),"dev",at-10,"the key TLK-INT-9f2a is fake"));
  for(int i=0;i<3;i++)signals.add(new FeedbackThemes.Signal(9,"review_outcome","REJECTED:noise","r"+i,"owner",at-20,"kept"));
  var themes=FeedbackThemes.build(signals).stream().map(t->{Map<String,Object> theme=new LinkedHashMap<>(t);theme.put("name","rule-"+t.get("rule_id"));theme.put("module",(Long)t.get("rule_id")==8?"Betterleaks":"Regex");return theme;}).toList();
  var summary=Map.of("themes",themes);
  database.records.insert(new RuleReviewReportEntity(UUID.randomUUID().toString(),null,"MANUAL","admin",1,at,AssistantState.mapper().writeValueAsString(summary)));
 }
 long spent(){return naming.spent(naming.weekStart());}
 @SuppressWarnings("unchecked") Map<String,Object> attached()throws Exception{
  String json=database.jdbc.queryForObject("SELECT summary_json FROM rule_review_reports",String.class);
  var summary=AssistantState.mapper().readValue(json,new TypeReference<Map<String,Object>>(){});
  return (Map<String,Object>)((Map<String,Object>)naming.attach(Map.of("report",Map.of("summary",summary))).get("report")).get("summary");
 }

 @Test void namesThemesOnceSendsNoSecretRuleTextAndRejectsUnsafeReplies()throws Exception{
  replies.add(reply(VALID));replies.add(reply(VALID));replies.add(reply(VALID.replace("dummy data","src/gen/Client.java")));
  naming.run();
  assertEquals(3,sent.size());
  var first=sent.get(0);assertEquals("fixture-model",first.model());assertEquals("low",first.effort());assertTrue(first.schema().has("properties"));
  assertTrue(first.input().contains("Generated test fixture"));assertFalse(first.input().contains("alice"));assertFalse(first.input().contains("Client.java"));
  var secret=sent.stream().filter(r->r.input().contains("rule-8")).findFirst().orElseThrow();
  assertFalse(secret.input().contains("TLK-INT"));assertTrue(secret.input().contains("not included"),"a secret rule's theme is named from counts and categories only");
  assertFalse(secret.input().contains("shared_terms"),"terms are built from the raw text, so a secret rule's terms are not sent");
  assertTrue(first.input().contains("shared_terms"));
  verify(secrets,never()).bypassesCoveringSecrets(any(),any());
  assertEquals(2,database.jdbc.queryForObject("SELECT COUNT(*) FROM rule_review_theme_names WHERE status='NAMED'",Integer.class));
  assertEquals(1,database.jdbc.queryForObject("SELECT COUNT(*) FROM rule_review_theme_names WHERE status='REJECTED'",Integer.class));
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM rule_review_theme_names WHERE name LIKE '%Client%' OR explanation LIKE '%Client%'",Integer.class));
  assertEquals(Boolean.FALSE,database.jdbc.queryForObject("SELECT text_sent FROM rule_review_theme_names WHERE rule_id=8",Boolean.class));
  assertEquals(3*1200L,spent(),"the worst case is settled to actual usage");
  naming.run();assertEquals(3,sent.size(),"unchanged themes reuse their row, including a rejected one");
  var summary=attached();@SuppressWarnings("unchecked") var themes=(List<Map<String,Object>>)summary.get("themes");@SuppressWarnings("unchecked") var status=(Map<String,Object>)summary.get("ai_naming");
  assertEquals("ON",status.get("state"));assertEquals(2,status.get("named"));assertEquals(3,status.get("themes"));
  @SuppressWarnings("unchecked") var ai=(Map<String,Object>)themes.get(0).get("ai");
  assertEquals("Fires on generated test fixtures",ai.get("name"));assertEquals("matches test or generated code",ai.get("cause_label"));assertEquals("fixture-model",ai.get("model"));
  assertTrue(themes.stream().anyMatch(t->t.get("ai") instanceof Map<?,?> m&&"REJECTED".equals(m.get("status"))));
 }
 @Test void aBypassThatAlsoCoveredASecretFindingIsLeftOutAndTheThemeLosesItsTerms()throws Exception{
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(),Set.of(),Set.of()));
  when(secrets.bypassesCoveringSecrets(any(),any())).thenReturn(Set.of(500L));
  for(long id:List.of(500L,501L,502L))database.jdbc.update("INSERT INTO pull_request_bypasses(bypass_id,api_label,repo_name,pr_id,scan_id,bypassed_by,reason,created_at,reason_code) VALUES (?,?,?,?,?,?,?,?,?)",
    id,"local","repo","42",9,"dev",id==500?"the key TLK-INT-9f2a is fake":"generated client stubs",now.get().toEpochMilli(),"TEST_CODE");
  naming.run();
  var bypass=sent.stream().filter(r->r.input().contains("rule-8")).findFirst().orElseThrow();
  assertTrue(bypass.input().contains("generated client stubs"));assertFalse(bypass.input().contains("TLK-INT"));assertFalse(bypass.input().contains("shared_terms"));
 }
 @Test void theWeeklyBudgetStopsNamingAndResumesNextWeek()throws Exception{
  configure(true,30000);
  for(int i=0;i<3;i++)replies.add(new OpenAiLlmClient.StructuredReply(VALID,false,"completed",0,0,false));
  naming.run();
  assertEquals(2,sent.size(),"unknown usage stays charged at the 12,096 micro worst case, so a third request would pass $0.03");
  assertEquals(2*12096L,spent());assertEquals("BUDGET_USED",naming.readiness().problem());
  assertTrue(naming.readiness().message().contains("$0.03"));
  now.set(now.get().plus(Duration.ofDays(7)));assertNull(naming.readiness().problem());naming.run();assertEquals(3,sent.size());
 }
 @Test void providerErrorsStopTheRunAndOnlyTransportFailuresStayCharged()throws Exception{
  replies.add(new LlmClient.ProviderFailure("PROVIDER_RATE_LIMIT",true,0));
  naming.run();assertEquals(1,sent.size());assertEquals(0L,spent(),"an error reply used nothing");
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM rule_review_theme_names",Integer.class));
  replies.add(new LlmClient.ProviderFailure("PROVIDER_TRANSPORT",true,0));
  naming.run();assertEquals(2,sent.size());assertEquals(12096L,spent(),"a timed-out request may have been charged");
 }
 @Test void offKeylessAndRejectedKeyStatesNeverCallTheProviderAndExplainWhy()throws Exception{
  configure(false,10_000_000);naming.run();assertEquals("OFF",naming.readiness().problem());
  @SuppressWarnings("unchecked") var status=(Map<String,Object>)attached().get("ai_naming");assertEquals("OFF",status.get("state"));assertTrue(((String)status.get("message")).contains("Assistant settings"));
  configure(true,10_000_000);keyConfigured.set(false);naming.run();assertEquals("NO_API_KEY",naming.readiness().problem());
  assertEquals(0,sent.size());
  assertThrows(IllegalArgumentException.class,()->configure(true,1000),"the budget must permit one worst-case request");
 }
 @Test void reportsWithoutFingerprintsAreLeftAlone()throws Exception{
  database.jdbc.update("DELETE FROM rule_review_reports");
  database.records.insert(new RuleReviewReportEntity(UUID.randomUUID().toString(),null,"MANUAL","admin",1,now.get().toEpochMilli(),"{\"themes\":[{\"rule_id\":7,\"source\":\"bypass\"}]}"));
  naming.run();assertEquals(0,sent.size());
  var view=Map.<String,Object>of("report",Map.of("summary",Map.of("counts",Map.of())));assertSame(view,naming.attach(view));
 }
}
