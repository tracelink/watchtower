package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.util.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

/** S0: feature switches default off, feature slices cap bulk work, and chat keeps room in the shared daily budget. */
class AssistantFeatureBudgetTest {
 static final String OLD_JSON="{\"enabled\":false,\"retentionDays\":14,\"allowedModels\":[],\"defaultModel\":\"\",\"defaultEffort\":\"\",\"maxIterations\":6,\"maxRequests\":9,\"maxInputBytes\":65536,\"maxOutputTokens\":2048,\"maxToolBytes\":16384,\"maxTranscriptBytes\":262144,\"turnTokenCap\":100000,\"userDailyTokens\":200000,\"orgDailyTokens\":2000000,\"turnCostMicros\":500000,\"userDailyCostMicros\":2000000,\"orgDailyCostMicros\":20000000,\"queueLimit\":50,\"deadlineSeconds\":600,\"providerTimeoutSeconds\":30}";
 @TempDir Path dir;AssistantFixture fx;AssistantSettingsService settings;AssistantPersistence db;AssistantBudgetService budgets;R1Database database;
 @BeforeEach void setup()throws Exception{fx=new AssistantFixture(dir,Set.of("Assistant Use"));settings=fx.settings;db=fx.db;budgets=fx.budgets;database=fx.database;}
 @AfterEach void close(){fx.close();}
 void configure(java.util.function.Consumer<ObjectNode> change)throws Exception{fx.configure(change);}
 static void slice(ObjectNode config,String feature,boolean on,long tokens,long cost){AssistantFixture.slice(config,feature,on,tokens,cost);}
 AssistantSettings cfg(){return fx.cfg();}
 AssistantSettings.Model model(){return fx.model();}
 long orgTokens(){return database.jdbc.queryForObject("SELECT COALESCE(SUM(charged_tokens),0) FROM assistant_budget_daily",Long.class);}

 @Test void settingsStoredBeforeFeaturesDecodeWithEveryFeatureOff(){
  var old=settings.decode(OLD_JSON);
  for(var feature:AssistantFeature.values()){assertFalse(old.isFeatureOn(feature),feature.key());assertTrue(old.featureSlice(feature).isEmpty(),feature.key());}
  assertTrue(AssistantFeature.ofKey("batchTriage").isPresent());assertTrue(AssistantFeature.ofKey("nonsense").isEmpty());
  var roundTrip=settings.decode(settings.encode(old));assertEquals(old.features(),roundTrip.features());
 }
 @Test void aSwitchableFeatureCannotBeOnWithoutItsSliceAndUnknownKeysAreRejected(){
  var json=(ObjectNode)AssistantState.mapper().valueToTree(settings.decode(OLD_JSON));
  json.putObject("features").putObject("enabled").put("batchTriage",true);
  assertThrows(IllegalArgumentException.class,()->settings.decode(json.toString()),"a bulk feature needs a daily slice");
  var unknown=(ObjectNode)AssistantState.mapper().valueToTree(settings.decode(OLD_JSON));unknown.putObject("features").putObject("enabled").put("autoApprove",true);
  assertThrows(IllegalArgumentException.class,()->settings.decode(unknown.toString()));
  var cards=(ObjectNode)AssistantState.mapper().valueToTree(settings.decode(OLD_JSON));cards.putObject("features").putObject("enabled").put("contextCards",true);
  assertTrue(settings.decode(cards.toString()).isFeatureOn(AssistantFeature.CONTEXT_CARDS),"chat context cards use the chat budget and need no slice");
  var assessment=(ObjectNode)AssistantState.mapper().valueToTree(settings.decode(OLD_JSON));assessment.putObject("features").putObject("enabled").put("findingAssessment",true);
  assertThrows(IllegalArgumentException.class,()->settings.decode(assessment.toString()),"finding assessment keeps its own switch");
 }
 @Test void slicesMustLeaveRoomForOneWorstCaseChatRequest()throws Exception{
  // One chat request reserves 65,536 + 2,048 tokens. An organization cap of 2,000,000 minus slices of 1,950,000 leaves too little.
  assertThrows(IllegalArgumentException.class,()->configure(c->slice(c,"batchTriage",true,1_950_000,1_000_000)));
  configure(c->slice(c,"batchTriage",true,1_000_000,1_000_000));
  assertTrue(cfg().isFeatureOn(AssistantFeature.BATCH_TRIAGE));
  assertThrows(IllegalArgumentException.class,()->configure(c->slice(c,"batchTriage",true,1_000_000,19_990_000)),"the cost cap needs the same room");
 }
 @Test void aFullSliceStopsBulkWorkWhileChatStillFits()throws Exception{
  configure(c->slice(c,"batchTriage",true,100_000,100_000));
  var cfg=cfg();var model=model();
  var first=budgets.reserveDirect("alice",cfg,model,60_000,2_048,AssistantFeature.BATCH_TRIAGE);
  assertEquals("batchTriage",first.feature());
  long before=orgTokens();
  var full=assertThrows(IllegalStateException.class,()->budgets.reserveDirect("bob",cfg,model,60_000,2_048,AssistantFeature.BATCH_TRIAGE));
  assertEquals("FEATURE_BUDGET",full.getMessage());
  assertEquals(before,orgTokens(),"a refused slice charge leaves the organization and user buckets untouched");
  assertFalse(budgets.canAfford("bob",cfg,model,60_000,2_048,AssistantFeature.BATCH_TRIAGE));
  assertTrue(budgets.canAfford("bob",cfg,model,60_000,2_048),"chat is not held back by the slice");
  assertNotNull(budgets.reserveDirect("bob",cfg,model,60_000,2_048));
 }
 @Test void settlingARefundsTheSliceAndTheSharedBuckets()throws Exception{
  configure(c->slice(c,"batchTriage",true,100_000,100_000));
  var cfg=cfg();var model=model();
  var charge=budgets.reserveDirect("alice",cfg,model,60_000,2_048,AssistantFeature.BATCH_TRIAGE);
  assertEquals(62_048L,budgets.usedToday(AssistantFeature.BATCH_TRIAGE).get("tokens"));
  budgets.settleDirect(charge,3_000,4_000);
  assertEquals(3_000L,budgets.usedToday(AssistantFeature.BATCH_TRIAGE).get("tokens"));assertEquals(4_000L,budgets.usedToday(AssistantFeature.BATCH_TRIAGE).get("cost_micros"));
  assertEquals(2*3_000L+3_000L,orgTokens(),"organization, user and slice buckets each settle to the actual 3,000 tokens");
  assertThrows(IllegalStateException.class,()->budgets.settleDirect(charge,charge.tokens()+1,0));
 }
 @Test void aRefusalNamesTheLimitThatWasHitSoItCanBeRaised()throws Exception{
  configure(c->slice(c,"batchTriage",true,100_000,100_000));
  var cfg=cfg();var model=model();
  assertNull(budgets.shortfall("bob",cfg,model,10_000,2_048,AssistantFeature.BATCH_TRIAGE),"it fits, so there is nothing to name");
  budgets.reserveDirect("alice",cfg,model,60_000,2_048,AssistantFeature.BATCH_TRIAGE);
  assertEquals("this feature's daily share",budgets.shortfall("bob",cfg,model,60_000,2_048,AssistantFeature.BATCH_TRIAGE));
  String message=AssistantBudgetService.limitMessage(AssistantFeature.BATCH_TRIAGE,budgets.shortfall("bob",cfg,model,60_000,2_048,AssistantFeature.BATCH_TRIAGE));
  assertTrue(message.contains("this feature's daily share")&&message.contains("AI assistant settings"),message);
  // a request larger than one person's whole daily token limit names that limit, not "the budget"
  var tooBig=budgets.shortfall("bob",cfg,model,cfg.userDailyTokens()+1,0,null);
  assertTrue(tooBig.contains("your daily token limit"),tooBig);
 }
 @Test void savingNoSettingsIsABadRequestNotAServerError(){
  assertThrows(IllegalArgumentException.class,()->fx.settings.save(null,"admin"));
  assertThrows(IllegalArgumentException.class,()->fx.settings.save(new AssistantSettingsService.Versioned(1,null),"admin"));
 }
 @Test void aFeatureWithoutASliceIsNamedAsSuch()throws Exception{
  assertEquals("this feature has no daily share set",budgets.shortfall("alice",cfg(),model(),10_000,2_048,AssistantFeature.BATCH_TRIAGE));
 }
 @Test void aBulkFeatureWithoutASliceIsRefusedRatherThanRunningOnTheWholeBudget()throws Exception{
  var cfg=cfg();var model=model();
  var e=assertThrows(IllegalStateException.class,()->budgets.reserveDirect("alice",cfg,model,10_000,2_048,AssistantFeature.BATCH_TRIAGE));
  assertEquals("FEATURE_BUDGET",e.getMessage());
  assertFalse(budgets.canAfford("alice",cfg,model,10_000,2_048,AssistantFeature.BATCH_TRIAGE));
  assertEquals(0L,orgTokens(),"nothing was charged");
 }
 @Test void aRefusedSliceChargeInATurnLeavesTheTurnAndBucketsUntouched()throws Exception{
  configure(c->slice(c,"alertCopilot",true,60_000,60_000));
  var turn=fx.claim("alice","Route alerts to the security channel");
  var e=assertThrows(IllegalStateException.class,()->budgets.reserve(turn,cfg(),model(),60_000,2_048,AssistantFeature.ALERT_COPILOT));
  assertEquals("FEATURE_BUDGET",e.getMessage());
  assertEquals(0L,orgTokens());
  assertEquals(0L,database.jdbc.queryForObject("SELECT tokens FROM assistant_turns WHERE turn_id=?",Long.class,turn.id()));
  assertEquals(0,database.jdbc.queryForObject("SELECT COUNT(*) FROM assistant_request_reservations",Integer.class));
 }
 @Test void nullAndOverflowingSliceSettingsAreValidationErrorsNotCrashes(){
  var withNull=new java.util.HashMap<String,AssistantSettings.Features.Slice>();withNull.put("batchTriage",null);
  assertThrows(IllegalArgumentException.class,()->new AssistantSettings.Features(Map.of(),withNull));
  var nullSwitch=new java.util.HashMap<String,Boolean>();nullSwitch.put("contextCards",null);
  assertThrows(IllegalArgumentException.class,()->new AssistantSettings.Features(nullSwitch,Map.of()));
  var nullSliceJson=(ObjectNode)AssistantState.mapper().valueToTree(settings.decode(OLD_JSON));
  nullSliceJson.putObject("features").putObject("slices").putNull("batchTriage");
  assertThrows(IllegalArgumentException.class,()->settings.decode(nullSliceJson.toString()));
  // The admin save path calls validate() directly, so an overflow must be an IllegalArgumentException there too.
  var huge=new AssistantSettings.Features(Map.of("batchTriage",true,"homeDigest",true),Map.of("batchTriage",new AssistantSettings.Features.Slice(Long.MAX_VALUE,1),"homeDigest",new AssistantSettings.Features.Slice(Long.MAX_VALUE,1)));
  var base=settings.decode(OLD_JSON);
  var oversized=new AssistantSettings(true,base.retentionDays(),fx.cfg().allowedModels(),"fixture-model","low",base.maxIterations(),base.maxRequests(),base.maxInputBytes(),base.maxOutputTokens(),base.maxToolBytes(),base.maxTranscriptBytes(),base.turnTokenCap(),base.userDailyTokens(),base.orgDailyTokens(),base.turnCostMicros(),base.userDailyCostMicros(),base.orgDailyCostMicros(),base.queueLimit(),base.deadlineSeconds(),base.providerTimeoutSeconds(),base.themeNaming(),base.findingAssessment(),false,huge);
  assertThrows(IllegalArgumentException.class,oversized::validate);
 }
 @Test void aFeatureWithoutASliceChargesOnlyTheSharedBuckets()throws Exception{
  var cfg=cfg();var model=model();
  var charge=budgets.reserveDirect("alice",cfg,model,24_000,2_048,AssistantFeature.FINDING_ASSESSMENT);
  assertNull(charge.feature(),"finding assessment keeps today's behavior until an admin gives it a slice");
  assertEquals(0L,budgets.usedToday(AssistantFeature.FINDING_ASSESSMENT).get("tokens"));
  assertEquals(2*26_048L,orgTokens());
 }
 @Test void aTurnReservationRecordsItsFeatureAndSettlementRefundsTheSlice()throws Exception{
  configure(c->slice(c,"alertCopilot",true,200_000,200_000));
  var t=db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"Route alerts to the security channel",null,null),"alice");
  var claimed=db.claim(t.id(),"pod-a").orElseThrow();
  var cfg=cfg();var model=model();
  var reservation=budgets.reserve(claimed,cfg,model,50_000,2_048,AssistantFeature.ALERT_COPILOT);
  assertEquals("alertCopilot",reservation.feature());
  assertEquals("alertCopilot",database.jdbc.queryForObject("SELECT feature FROM assistant_request_reservations WHERE reservation_id=?",String.class,reservation.id()));
  assertEquals(52_048L,budgets.usedToday(AssistantFeature.ALERT_COPILOT).get("tokens"));
  budgets.settle(claimed,reservation,1_000,1_500);
  assertEquals(1_000L,budgets.usedToday(AssistantFeature.ALERT_COPILOT).get("tokens"));
  budgets.settle(claimed,reservation,1_000,1_500);
  assertEquals(1_000L,budgets.usedToday(AssistantFeature.ALERT_COPILOT).get("tokens"),"settlement is idempotent");
  var plain=budgets.reserve(claimed,cfg,model,10_000,2_048);
  assertNull(plain.feature());assertNull(database.jdbc.queryForObject("SELECT feature FROM assistant_request_reservations WHERE reservation_id=?",String.class,plain.id()));
 }
}
