package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import com.tracelink.appsec.watchtower.core.assistant.assessment.FindingAiExposureRepository;
import com.tracelink.appsec.watchtower.core.assistant.assessment.FindingAiExposures;
import com.tracelink.appsec.watchtower.core.assistant.assessment.FindingAssessmentRepository;
import com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService;
import com.tracelink.appsec.watchtower.core.assistant.assessment.FindingLocator;
import com.tracelink.appsec.watchtower.core.assistant.context.*;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/** S1: the page sends ids only; the server rebuilds, grant-checks and secret-checks the card on every turn. */
class AssistantContextTest {
 static final Set<String> GRANTS=Set.of("Assistant Use","Scan Results View","Ruleset View","Repository Settings View");
 static final String OCC="o".repeat(64);
 @TempDir Path dir;AssistantFixture fx;FindingLocator locator;AssistantSecretFindings secrets;ContextService contexts;RuleDto rule;RepositoryEntity repo;
 final AtomicReference<Set<String>> held=new AtomicReference<>(GRANTS);
 ContextRequest finding(String key){return new ContextRequest(1,"finding",new ContextRequest.Ids("pull_request",5L,key,null,null));}
 FindingLocator.Detail detail(boolean sensitive,String message){
  var located=new FindingLocator.Located("pull_request",5,"9",OCC,7L,"a".repeat(64),repo,"c".repeat(40),"src/OrderController.java",88,sensitive,null);
  return new FindingLocator.Detail(located,"xss-output","PMD","HIGH",message,"Payments API");
 }
 @BeforeEach void setup()throws Exception{
  fx=new AssistantFixture(dir,GRANTS);
  when(fx.access.authorities(anyString())).thenAnswer(i->held.get());
  fx.configure(c->{var features=c.putObject("features");features.putObject("enabled").put("contextCards",true);});
  locator=mock(FindingLocator.class);secrets=mock(AssistantSecretFindings.class);repo=mock(RepositoryEntity.class);when(repo.getRepoName()).thenReturn("payments-api");
  var entity=mock(RuleEntity.class);rule=mock(RuleDto.class);when(fx.rules.getRule(7L)).thenReturn(entity);when(entity.toDto()).thenReturn(rule);
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(),Set.of(),Set.of()));
  when(locator.locateDetailed("pull_request",5,"9")).thenAnswer(i->detail(false,"Unescaped output"));
  var provider=new FindingContextProvider(locator,fx.rules,secrets,fx.database.records,fx.database.repository(FindingAssessmentRepository.class));
  contexts=new ContextService(fx.access,fx.settings,List.of(provider));
 }
 @AfterEach void close(){fx.close();}
 /** Runs one turn with the given card and a scripted model; returns how many model calls it made. */
 int run(ContextCard card,String text,java.util.function.Consumer<LlmClient.Request> inspect)throws Exception{
  var turn=fx.db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),text,null,null,card==null?null:finding("9")),"alice",card);
  var claimed=fx.db.claim(turn.id(),"pod-a").orElseThrow();var calls=new AtomicInteger();
  LlmClient scripted=request->{calls.incrementAndGet();inspect.accept(request);return AssistantFixture.answer("It looks like a likely false positive; you decide.");};
  var runner=new AssistantTurnRunner(fx.db,fx.settings,fx.tools,scripted,fx.budgets);runner.setContexts(contexts);runner.run(claimed);
  lastTurn=claimed;return calls.get();
 }
 AssistantPersistence.Turn lastTurn;
 String answer()throws Exception{return fx.db.state(fx.db.turn(lastTurn.id())).answer;}

 @Test void aChatAnswerAboutAFindingRecordsThatThePersonSawAnAiOpinionOfIt()throws Exception{
  var exposures=new FindingAiExposures(fx.database.repository(FindingAiExposureRepository.class),fx.database.tx);
  var key=FindingFeedbackService.occurrenceKey("pull_request",5,"9");
  var card=contexts.forSubmit("alice",finding("9"));
  var turn=fx.db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"Is this a false positive?",null,null,finding("9")),"alice",card);
  var claimed=fx.db.claim(turn.id(),"pod-a").orElseThrow();
  var runner=new AssistantTurnRunner(fx.db,fx.settings,fx.tools,request->AssistantFixture.answer("Likely a false positive; you decide."),fx.budgets);runner.setContexts(contexts);runner.setExposures(exposures);
  assertEquals(0,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_ai_exposure",Integer.class),"nothing before an answer exists");
  runner.run(claimed);
  assertEquals("CHAT",fx.database.jdbc.queryForObject("SELECT source FROM finding_ai_exposure WHERE occurrence_key=? AND viewer='alice'",String.class,key));
 }
 @Test void aBlockedFindingAndAnUnrelatedPageRecordNoExposure()throws Exception{
  var exposures=new FindingAiExposures(fx.database.repository(FindingAiExposureRepository.class),fx.database.tx);
  when(secrets.isSecretRule(rule)).thenReturn(true);
  var blocked=contexts.forSubmit("alice",finding("9"));
  var turn=fx.db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"Is this a false positive?",null,null,finding("9")),"alice",blocked);
  var runner=new AssistantTurnRunner(fx.db,fx.settings,fx.tools,request->{throw new AssertionError("no model call");},fx.budgets);runner.setContexts(contexts);runner.setExposures(exposures);
  runner.run(fx.db.claim(turn.id(),"pod-a").orElseThrow());
  var plain=fx.db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"How do rulesets work?",null,null),"alice");
  var plainRunner=new AssistantTurnRunner(fx.db,fx.settings,fx.tools,request->AssistantFixture.answer("Rulesets group rules."),fx.budgets);plainRunner.setExposures(exposures);
  plainRunner.run(fx.db.claim(plain.id(),"pod-a").orElseThrow());
  assertEquals(0,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_ai_exposure",Integer.class));
 }
 @Test void readingAFindingWithAToolCountsEvenWhenThePageIsSomethingElse()throws Exception{
  var exposures=new FindingAiExposures(fx.database.repository(FindingAiExposureRepository.class),fx.database.tx);
  var provider=new FindingContextProvider(locator,fx.rules,secrets,fx.database.records,fx.database.repository(FindingAssessmentRepository.class));
  var set=new com.tracelink.appsec.watchtower.core.assistant.tools.ContextTools(provider,mock(RepositoryContextProvider.class),mock(PullRequestContextProvider.class),mock(ScanSummaries.class),mock(org.springframework.beans.factory.ObjectProvider.class));
  fx.tools.setSettings(fx.settings);set.tools().forEach(fx.tools::register);
  var turn=fx.claim("alice","What do you think of finding 9 on scan 5?");var calls=new AtomicInteger();
  LlmClient scripted=request->calls.getAndIncrement()==0?AssistantFixture.toolCall("get_finding","{\"finding_key\":\"9\",\"scan_id\":5,\"scan_type\":\"pull_request\"}"):AssistantFixture.answer("It looks like a likely false positive.");
  var runner=new AssistantTurnRunner(fx.db,fx.settings,fx.tools,scripted,fx.budgets);runner.setExposures(exposures);runner.run(turn);
  assertEquals(1,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM finding_ai_exposure WHERE occurrence_key=?",Integer.class,FindingFeedbackService.occurrenceKey("pull_request",5,"9")));
 }
 FindingLocator.Detail unlocated(Long ruleId,String ruleName,String message){
  var located=new FindingLocator.Located("pull_request",5,"9",OCC,ruleId,null,null,null,null,0,false,"The repository is not in Watchtower's catalog, so its source cannot be read.");
  return new FindingLocator.Detail(located,ruleName,"PMD","HIGH",message,"Payments API");
 }
 @Test void aFindingWhoseLineCannotBeCheckedKeepsTheScannerMessageAndLocationOut()throws Exception{
  when(locator.locateDetailed("pull_request",5,"9")).thenAnswer(i->unlocated(7L,"xss-output","token=abc123def456 on this line"));
  var card=contexts.forSubmit("alice",finding("9"));
  assertTrue(card.isOk());assertEquals("Finding · xss-output",card.title());
  var json=AssistantState.mapper().writeValueAsString(card);
  assertFalse(json.contains("abc123"));assertFalse(json.contains("message_untrusted"));assertFalse(card.facts().containsKey("path"));assertFalse(card.facts().containsKey("line"));
  verify(secrets,never()).isRecordedSecretLine(any(),any(),anyInt(),anyCollection());
 }
 @Test void aFindingWhoseRuleIsNotKnownAtAllIsBlockedBecauseItCannotBeToldFromASecret()throws Exception{
  when(locator.locateDetailed("pull_request",5,"9")).thenAnswer(i->unlocated(null,null,"unknown"));
  assertTrue(contexts.forSubmit("alice",finding("9")).isBlocked(),"an expired report or legacy row");
 }
 @Test void aRepositoryScanFindingChecksEveryRecordedSecretLineOfTheRepository()throws Exception{
  var located=new FindingLocator.Located("repository",4,"k",OCC,7L,"a".repeat(64),repo,"c".repeat(40),"src/OrderController.java",88,false,null);
  when(locator.locateDetailed("repository",4,"k")).thenReturn(new FindingLocator.Detail(located,"xss-output","PMD","HIGH","m","payments-api"));
  var request=new ContextRequest(1,"finding",new ContextRequest.Ids("repository",4L,"k",null,null));
  when(secrets.lines(repo)).thenReturn(new AssistantSecretFindings.Lines(Map.of("src/OrderController.java",Map.of(88,"Betterleaks"))));
  assertTrue(contexts.forSubmit("alice",request).isBlocked(),"a secret recorded on this line by another scan's engine");
  when(secrets.lines(repo)).thenReturn(new AssistantSecretFindings.Lines(Map.of()));
  assertTrue(contexts.forSubmit("alice",request).isOk());
  verify(secrets,never()).isRecordedSecretLine(any(),any(),anyInt(),anyCollection());
 }
 @Test void ruleNamesAreMatchedIgnoringCaseLikeTheDatabaseDoes(){
  var secret=new AssistantSecretFindings.SecretRules(Set.of(),Set.of("Generic-API-Key"),Set.of());
  assertTrue(secret.contains(null,null,"generic-api-key"));assertTrue(secret.contains(null,null,"GENERIC-API-KEY"));assertFalse(secret.contains(null,null,"generic-api-keys"));
 }
 @Test void aRebuiltCardEqualsTheStoredOneEvenThoughStoredNumbersAreSmallerTypes()throws Exception{
  var card=contexts.forSubmit("alice",finding("9"));
  var stored=AssistantState.mapper().readTree(AssistantState.mapper().writeValueAsString(card));
  assertFalse(AssistantState.mapper().valueToTree(card).equals(stored),"the trap: Long and Int nodes differ");
  assertTrue(AssistantTurnRunner.sameCard(card,stored));
  assertFalse(AssistantTurnRunner.sameCard(ContextCard.blocked("finding",card.ids()),stored));
 }
 @Test void aReplacedCardKeepsItsPlaceInTheConversation(){
  var first=contexts.forSubmit("alice",finding("9"));
  var state=new AssistantState();state.user("one");state.useContext(first);
  state.protocol.addObject().put("type","function_call").put("call_id","c1").put("name","get_rule").put("arguments","{}");
  state.useContext(first);
  assertEquals(2,java.util.stream.IntStream.range(0,state.protocol.size()).filter(i->state.protocol.get(i).has("role")).count());
  assertEquals("function_call",state.protocol.get(2).path("type").asText(),"the card stays beside the question, not after the pending tool call");
 }
 @Test void aTokenNearTheCutIsRedactedBeforeTheMessageIsShortened()throws Exception{
  when(locator.locateDetailed("pull_request",5,"9")).thenAnswer(i->detail(false,"a".repeat(191)+" sk-abcdefghijklmnopqrstuvwxyz"));
  var json=AssistantState.mapper().writeValueAsString(contexts.forSubmit("alice",finding("9")));
  assertFalse(json.contains("sk-abc"),"no part of the token survives the cut");
 }
 @Test void aHugeTitleStillFitsTheCardLimit()throws Exception{
  ContextProvider huge=new ContextProvider(){
   public String kind(){return "rule";}public Set<String> grants(){return Set.of();}
   public ContextCard resolve(ContextRequest.Ids ids){return ContextCard.ok("rule","T".repeat(5000),Map.of("x","y".repeat(5000)),Map.of());}
  };
  var service=new ContextService(fx.access,fx.settings,List.of(huge));
  var card=service.forSubmit("alice",new ContextRequest(1,"rule",new ContextRequest.Ids(null,null,null,null,1L)));
  assertTrue(AssistantState.mapper().writeValueAsString(card).getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=ContextService.MAX_CARD_BYTES);
 }
 @Test void aPageRequestWithoutContextKeepsTheSameRequestHashAsBefore()throws Exception{
  var key=UUID.randomUUID().toString();
  fx.db.submit(new AssistantPersistence.Submit(null,key,"Explain this",null,null),"alice");
  var expected=com.tracelink.appsec.watchtower.core.rule.RuleRevision.definition("assistant-submit","v1").field("task",null).field("message","Explain this").field("session",null).field("model",null).field("effort",null).hash();
  assertEquals(expected,fx.database.jdbc.queryForObject("SELECT request_hash FROM assistant_turns WHERE idempotency_key=?",String.class,key),"a retry of a turn accepted before this change still matches");
  assertTrue(fx.db.hasTurn("alice",key));assertFalse(fx.db.hasTurn("bob",key));assertFalse(fx.db.hasTurn("alice",UUID.randomUUID().toString()));assertFalse(fx.db.hasTurn("alice","not-a-uuid"));
 }
 @Test void toolOutputKeptFromAnEarlierTurnIsReplacedOnceTheFindingBecomesSecret()throws Exception{
  var provider=new FindingContextProvider(locator,fx.rules,secrets,fx.database.records,fx.database.repository(FindingAssessmentRepository.class));
  var set=new com.tracelink.appsec.watchtower.core.assistant.tools.ContextTools(provider,mock(RepositoryContextProvider.class),mock(PullRequestContextProvider.class),mock(ScanSummaries.class),mock(org.springframework.beans.factory.ObjectProvider.class));
  fx.tools.setSettings(fx.settings);set.tools().forEach(fx.tools::register);
  var first=fx.claim("alice","Look at finding 9");var calls=new AtomicInteger();
  LlmClient reads=request->calls.getAndIncrement()==0?AssistantFixture.toolCall("get_finding","{\"finding_key\":\"9\",\"scan_id\":5,\"scan_type\":\"pull_request\"}"):AssistantFixture.answer("Looks fine.");
  var runner=new AssistantTurnRunner(fx.db,fx.settings,fx.tools,reads,fx.budgets);runner.setContexts(contexts);runner.run(first);
  assertTrue(fx.db.state(fx.db.turn(first.id())).protocol.toString().contains("OrderController"),"the first turn read the finding");
  // The rule is reclassified as a secret rule; a later turn in the same chat must not resend what was read.
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(7L),Set.of(),Set.of()));
  var second=fx.db.submit(new AssistantPersistence.Submit(first.session(),UUID.randomUUID().toString(),"And what about rulesets?",null,null),"alice");
  var sent=new ArrayList<String>();
  var later=new AssistantTurnRunner(fx.db,fx.settings,fx.tools,request->{sent.add(request.input().toString());return AssistantFixture.answer("Rulesets group rules.");},fx.budgets);later.setContexts(contexts);
  later.run(fx.db.claim(second.id(),"pod-b").orElseThrow());
  assertEquals(1,sent.size());assertFalse(sent.getFirst().contains("OrderController"));assertTrue(sent.getFirst().contains("secret finding"));
 }
 @Test void thePreviewForTheChipSaysHowThePageWasUnderstoodInPlainWords()throws Exception{
  var ok=contexts.preview("alice",finding("9"));
  assertEquals("OK",ok.state());assertEquals("xss-output · OrderController.java:88",ok.label());assertEquals("Finding · xss-output · src/OrderController.java:88",ok.title());
  assertEquals(List.of("HIGH","Not reviewed · no AI assessment yet","src/OrderController.java line 88"),ok.lines().subList(0,3).stream().map(l->l.startsWith("HIGH")?"HIGH":l).toList());
  assertFalse(AssistantState.mapper().writeValueAsString(ok).contains("Unescaped output"),"scanner text is not part of the chip");
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(7L),Set.of(),Set.of()));
  var blocked=contexts.preview("alice",finding("9"));
  assertEquals("BLOCKED",blocked.state());assertNull(blocked.label());assertNull(blocked.title());assertTrue(blocked.lines().isEmpty(),"nothing about a secret finding reaches the page");
  assertEquals("UNAVAILABLE",contexts.preview("alice",new ContextRequest(1,"dashboard",new ContextRequest.Ids(null,null,null,null,null))).state());
  fx.configure(c->c.putObject("features").putObject("enabled").put("contextCards",false));
  assertEquals("NONE",contexts.preview("alice",finding("9")).state(),"switched off: no chip details");
  assertEquals("NONE",contexts.preview("alice",null).state());
 }
 @Test void theBudgetListsEachFeatureShareSoAFullShareIsExplained()throws Exception{
  fx.configure(c->AssistantFixture.slice(c,"alertCopilot",true,200_000,200_000));
  fx.budgets.reserveDirect("alice",fx.cfg(),fx.model(),50_000,2_048,AssistantFeature.ALERT_COPILOT);
  var auth=mock(org.springframework.security.core.Authentication.class);when(auth.getName()).thenReturn("alice");
  var controller=new AssistantController(fx.db,fx.settings,fx.access,fx.tools,mock(AssistantStreams.class),fx.budgets);
  @SuppressWarnings("unchecked") var view=(Map<String,Object>)controller.budget(auth);
  assertEquals(fx.cfg().orgDailyCostMicros(),view.get("orgDailyCostMicros"));assertTrue(((Number)view.get("orgUsedCostMicros")).longValue()>0);
  @SuppressWarnings("unchecked") var features=(List<Map<String,Object>>)view.get("features");
  assertEquals(1,features.size());assertEquals("Alert-route copilot",features.getFirst().get("name"));assertEquals(200_000L,features.getFirst().get("dailyCostMicros"));assertTrue(((Number)features.getFirst().get("usedCostMicros")).longValue()>0);
 }
 @Test void anUnknownKindVersionOrMissingIdsGivesContextUnavailableAndNoException(){
  assertEquals(ContextCard.UNAVAILABLE,contexts.forSubmit("alice",new ContextRequest(1,"dashboard-of-doom",new ContextRequest.Ids(null,null,null,null,null))).state());
  assertEquals(ContextCard.UNAVAILABLE,contexts.forSubmit("alice",new ContextRequest(2,"finding",new ContextRequest.Ids("pull_request",5L,"9",null,null))).state());
  assertEquals(ContextCard.UNAVAILABLE,contexts.forSubmit("alice",new ContextRequest(1,"finding",null)).state());
  assertEquals(ContextCard.UNAVAILABLE,contexts.forSubmit("alice",new ContextRequest(1,"finding",new ContextRequest.Ids("upload",5L,"9",null,null))).state());
  assertNull(contexts.forSubmit("alice",null));
 }
 @Test void forgedOrMismatchedIdsAreUnavailableAndChatStillWorks()throws Exception{
  when(locator.locateDetailed("pull_request",5,"404")).thenThrow(new ResponseStatusException(HttpStatus.NOT_FOUND,"Unknown finding"));
  var card=contexts.forSubmit("alice",finding("404"));
  assertEquals(ContextCard.UNAVAILABLE,card.state());assertTrue(card.facts().isEmpty());
  assertEquals(1,run(card,"Is this a false positive?",r->{ }),"the model is still asked, without a page");
  assertFalse(fx.db.state(fx.db.turn(lastTurn.id())).protocol.toString().contains(AssistantState.CONTEXT_PREFIX));
 }
 @Test void aMissingGrantGivesNoCardAndRevokedAccessStopsAStoredCard()throws Exception{
  held.set(Set.of("Assistant Use"));
  assertEquals(ContextCard.UNAVAILABLE,contexts.forSubmit("alice",finding("9")).state());
  held.set(GRANTS);var card=contexts.forSubmit("alice",finding("9"));assertTrue(card.isOk());
  held.set(Set.of("Assistant Use"));
  assertThrows(AccessDeniedException.class,()->contexts.revalidate("alice",card));
 }
 @Test void aCardIsBuiltFromTheScanNotThePageAndReachesTheModelAsUntrustedData()throws Exception{
  var card=contexts.forSubmit("alice",finding("9"));
  assertTrue(card.isOk());assertEquals("Finding · xss-output · src/OrderController.java:88",card.title());
  assertEquals("HIGH",card.facts().get("severity"));assertEquals("NONE",card.facts().get("judgment"));assertEquals(false,card.facts().get("assessment_available"));
  var seen=new ArrayList<String>();
  assertEquals(1,run(card,"Is this a false positive?",r->seen.add(r.input().toString())));
  assertTrue(seen.getFirst().contains(AssistantState.CONTEXT_PREFIX.substring(0,30)));assertTrue(seen.getFirst().contains("src/OrderController.java"));assertTrue(seen.getFirst().contains("untrusted"));
 }
 @Test void aCardIsRedactedAndNeverLargerThanTwoKilobytes()throws Exception{
  when(locator.locateDetailed("pull_request",5,"9")).thenAnswer(i->detail(false,"password=hunter2hunter2 "+"x".repeat(5000)));
  var card=contexts.forSubmit("alice",finding("9"));
  assertTrue(card.isOk());var json=AssistantState.mapper().writeValueAsString(card);
  assertFalse(json.contains("hunter2"));assertTrue(json.getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=ContextService.MAX_CARD_BYTES,json.length()+" bytes");
 }
 @Test void aSecretRuleGivesOnlyTheBlockedMarkerAndTheModelIsNeverCalled()throws Exception{
  when(secrets.isSecretRule(rule)).thenReturn(true);
  var card=contexts.forSubmit("alice",finding("9"));
  assertTrue(card.isBlocked());assertEquals(ContextCard.BLOCKED_TITLE,card.title());assertTrue(card.facts().isEmpty());
  var json=AssistantState.mapper().writeValueAsString(card);
  for(String leak:List.of("OrderController","xss-output","88","PMD","Payments"))assertFalse(json.contains(leak),leak);
  assertEquals(0,run(card,"Is this a false positive?",r->fail("no model call for a secret finding")));
  assertEquals(AssistantTurnRunner.BLOCKED_ANSWER,answer());assertEquals("COMPLETED",fx.db.turn(lastTurn.id()).status());
  assertEquals(0,fx.database.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_request_reservations",Integer.class),"nothing was reserved or charged");
 }
 @Test void aPullRequestFindingOnASecretRuleIsBlockedEvenThoughItIsNotFlaggedSensitive()throws Exception{
  // sensitive=false is all the locator knows for pull request findings; the rule decides.
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(7L),Set.of(),Set.of()));
  assertTrue(contexts.forSubmit("alice",finding("9")).isBlocked());
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(),Set.of("xss-output"),Set.of()));
  assertTrue(contexts.forSubmit("alice",finding("9")).isBlocked(),"a legacy finding is matched by rule name");
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(),Set.of(),Set.of("pmd")));
  assertTrue(contexts.forSubmit("alice",finding("9")).isBlocked(),"or by a sensitive scanner module");
  when(locator.locateDetailed("pull_request",5,"9")).thenAnswer(i->detail(true,"m"));
  when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(),Set.of(),Set.of()));
  assertTrue(contexts.forSubmit("alice",finding("9")).isBlocked(),"and a finding flagged sensitive by its scan");
 }
 @Test void aRecordedSecretLineOrAFailedSecretCheckBlocksTheFinding()throws Exception{
  when(secrets.isRecordedSecretLine(eq(repo),eq("src/OrderController.java"),eq(88),anyCollection())).thenReturn(true);
  assertTrue(contexts.forSubmit("alice",finding("9")).isBlocked());
  when(secrets.isRecordedSecretLine(any(),any(),anyInt(),anyCollection())).thenThrow(new AssistantSecretFindings.Unavailable("down"));
  assertTrue(contexts.forSubmit("alice",finding("9")).isBlocked(),"fail closed");
  reset(secrets);when(secrets.secretRules()).thenThrow(new AssistantSecretFindings.Unavailable("down"));
  assertTrue(contexts.forSubmit("alice",finding("9")).isBlocked(),"fail closed when the rule list cannot be read");
 }
 @Test void aTurnRecoveredOnAnotherPodChecksThePageAgain()throws Exception{
  var card=contexts.forSubmit("alice",finding("9"));assertTrue(card.isOk());
  var turn=fx.db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"Is this a false positive?",null,null,finding("9")),"alice",card);
  // Before the turn runs, the rule is reclassified as a secret rule.
  when(secrets.isSecretRule(rule)).thenReturn(true);
  var claimed=fx.db.claim(turn.id(),"pod-b").orElseThrow();
  var runner=new AssistantTurnRunner(fx.db,fx.settings,fx.tools,request->{throw new AssertionError("no model call");},fx.budgets);runner.setContexts(contexts);runner.run(claimed);
  assertEquals("COMPLETED",fx.db.turn(turn.id()).status());assertEquals(AssistantTurnRunner.BLOCKED_ANSWER,fx.db.state(fx.db.turn(turn.id())).answer);
  assertTrue(fx.db.state(fx.db.turn(turn.id())).card().isBlocked());
 }
 @Test void aGrantRevokedBeforeTheTurnRunsFailsTheTurnWithoutAModelCall()throws Exception{
  var card=contexts.forSubmit("alice",finding("9"));
  var turn=fx.db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"Is this a false positive?",null,null,finding("9")),"alice",card);
  held.set(Set.of("Assistant Use"));
  var claimed=fx.db.claim(turn.id(),"pod-b").orElseThrow();
  var runner=new AssistantTurnRunner(fx.db,fx.settings,fx.tools,request->{throw new AssertionError("no model call");},fx.budgets);runner.setContexts(contexts);runner.run(claimed);
  assertEquals("FAILED",fx.db.turn(turn.id()).status());assertEquals("ACCESS_REVOKED",fx.db.turn(turn.id()).error());
 }
 @Test void theSameIdempotencyKeyWithADifferentPageIsAConflict()throws Exception{
  String key=UUID.randomUUID().toString();
  fx.db.submit(new AssistantPersistence.Submit(null,key,"Explain this",null,null,finding("9")),"alice");
  assertEquals(HttpStatus.CONFLICT,assertThrows(ResponseStatusException.class,()->fx.db.submit(new AssistantPersistence.Submit(null,key,"Explain this",null,null,finding("10")),"alice")).getStatusCode());
  assertDoesNotThrow(()->fx.db.submit(new AssistantPersistence.Submit(null,key,"Explain this",null,null,finding("9")),"alice"),"the same page is the same request");
 }
 @Test void contextIsIgnoredWhileTheSwitchIsOff()throws Exception{
  fx.configure(c->c.putObject("features").putObject("enabled").put("contextCards",false));
  assertNull(contexts.forSubmit("alice",finding("9")));
  fx.configure(c->c.putObject("features").putObject("enabled").put("contextCards",true));
  var card=contexts.forSubmit("alice",finding("9"));
  fx.configure(c->c.putObject("features").putObject("enabled").put("contextCards",false));
  assertEquals(ContextCard.UNAVAILABLE,contexts.revalidate("alice",card).state(),"a recovered turn drops the card once the switch is off");
 }
 @Test void aNewTurnReplacesTheEarlierPageCardInsteadOfPilingThemUp()throws Exception{
  var first=contexts.forSubmit("alice",finding("9"));
  var state=new AssistantState();state.user("one");state.useContext(first);
  assertEquals(2,state.protocol.size());assertTrue(state.protocol.toString().contains(AssistantState.CONTEXT_PREFIX));
  state.user("two");
  assertEquals(2,state.protocol.size(),"the old card left with the old question");assertNull(state.context);assertFalse(state.protocol.toString().contains(AssistantState.CONTEXT_PREFIX));
  state.useContext(first);state.useContext(ContextCard.blocked("finding",Map.of()));
  assertTrue(state.card().isBlocked());assertFalse(state.protocol.toString().contains(AssistantState.CONTEXT_PREFIX),"a blocked card is never shown to the model");
 }
}
