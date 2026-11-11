package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.actions.RulesetActions;
import com.tracelink.appsec.watchtower.core.assistant.actions.RulesetChangeSetService;
import com.tracelink.appsec.watchtower.core.assistant.features.*;
import com.tracelink.appsec.watchtower.core.feedback.MissedVulnerabilityService;
import com.tracelink.appsec.watchtower.core.feedback.RegressionProposalService;
import com.tracelink.appsec.watchtower.core.persistence.MissedVulnerabilityCaseEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/** S5: a ruleset suggestion and a fixture draft only advise, send no repository name, no secret and keep no code. */
class AssistantRepositoryHelpersTest {
 static final Set<String> GRANTS=Set.of("Assistant Use","Repository Settings View","Repository Settings Modify","Ruleset View","Ruleset Modify","Assistant Source Read","Scan Results View");
 @TempDir Path dir;AssistantFixture fx;StructuredFeatureCall calls;RulesetChangeSetService changes;OnboardingService onboarding;
 final List<OpenAiLlmClient.Structured> sent=new ArrayList<>();final Deque<OpenAiLlmClient.StructuredReply> replies=new ArrayDeque<>();
 final List<RulesetActions.Request> prepared=new ArrayList<>();
 long defaultSet,strictSet,supportSet,target;

 static OpenAiLlmClient.StructuredReply reply(String text){return new OpenAiLlmClient.StructuredReply(text,false,"completed",1200,60,true);}
 @BeforeEach void setup()throws Exception{
  fx=new AssistantFixture(dir,GRANTS);
  fx.configure(c->{c.put("rulesetActionsEnabled",true);AssistantFixture.slice(c,"onboarding",true,200_000,200_000);AssistantFixture.slice(c,"missedCase",true,200_000,200_000);});
  calls=new StructuredFeatureCall(fx.settings,R1Database.keys(fx.keyConfigured),fx.budgets,request->{sent.add(request);return replies.poll();});
  changes=mock(RulesetChangeSetService.class);
  when(changes.prepare(any(),anyString(),isNull())).thenAnswer(i->{prepared.add(i.getArgument(0));return new RulesetActions.View("cs-1",1,"DRAFT","hash",0,null,null);});
  onboarding=new OnboardingService(calls,fx.database.records,changes,fx.access,fx.settings);
  // The ORM test schema turns the @OneToOne ruleset into a unique column; the real schema lets many repositories share a ruleset.
  for(var name:fx.database.jdbc.queryForList("SELECT constraint_name FROM information_schema.table_constraints WHERE table_name='repositories' AND constraint_type IN ('UNIQUE','FOREIGN KEY')",String.class))fx.database.jdbc.execute("ALTER TABLE repositories DROP CONSTRAINT \""+name+"\"");
  for(var name:fx.database.jdbc.queryForList("SELECT index_name FROM information_schema.indexes WHERE table_name='repositories' AND index_type_name='UNIQUE INDEX'",String.class))fx.database.jdbc.execute("DROP INDEX \""+name+"\"");
  defaultSet=ruleset("Default Dev Ruleset","The usual rules for application code",RulesetDesignation.PRIMARY);
  strictSet=ruleset("Strict","Blocks on medium findings too",RulesetDesignation.PRIMARY);
  supportSet=ruleset("Shared helpers","Used by other rulesets",RulesetDesignation.SUPPORTING);
  for(int i=0;i<3;i++)repository("payments-"+i,"Java",defaultSet);
  repository("ledger","Java",strictSet);repository("website","JavaScript",strictSet);
  target=repository("wt-test-core","Java",null);
 }
 @AfterEach void close(){fx.close();}

 long ruleset(String name,String description,RulesetDesignation designation){
  return new TransactionTemplate(fx.database.tx).execute(s->{var r=new RulesetEntity();r.setName(name);r.setDescription(description);r.setDesignation(designation);fx.database.records.insert(r);return r.getId();});
 }
 long repository(String name,String language,Long ruleset){
  return new TransactionTemplate(fx.database.tx).execute(s->{var r=new RepositoryEntity();r.setApiLabel("Bitbucket");r.setRepoName(name);r.setScanType(com.tracelink.appsec.watchtower.core.scan.code.CodeScanType.PULL_REQUEST);r.setPrimaryLanguage(language);
   if(ruleset!=null)r.setRuleset(fx.database.records.find(RulesetEntity.class,ruleset));fx.database.records.insert(r);return r.getId();});
 }
 String pick(long id,String reason){return "{\"ruleset_id\":"+id+",\"reason\":\""+reason+"\"}";}

 @Test void aSuggestionIsOneOfTheCandidatesAndBecomesADraftForAPersonToReview(){
  replies.add(reply(pick(defaultSet,"Most Java repositories already use it.")));
  var out=onboarding.suggest("alice",target);
  assertEquals("OK",out.get("state"));assertEquals("cs-1",out.get("changeSetId"));assertEquals("/assistant/change-sets/cs-1/review",out.get("reviewUrl"));
  assertEquals(Map.of("using",3L,"total",4L),out.get("peers"),"counted from the repositories, not written by the model");
  assertEquals("Most Java repositories already use it.",out.get("reason"));assertNull(out.get("current"));
  var op=prepared.getFirst().operations().getFirst();
  assertEquals(RulesetActions.Type.ASSIGN,op.type());assertEquals(String.valueOf(defaultSet),op.target());assertEquals(List.of(target),op.repositoryIds());
  assertEquals(1,prepared.size());assertEquals(1,prepared.getFirst().operations().size(),"one assignment and nothing else");
  var input=sent.getFirst().input();
  assertTrue(input.contains("Default Dev Ruleset"));assertTrue(input.contains("Java"));
  assertFalse(input.contains("Shared helpers"),"a supporting ruleset cannot be assigned, so it is not offered");
  assertFalse(input.contains("payments")||input.contains("wt-test-core")||input.contains("ledger"),"no repository name is sent");
  assertTrue(fx.budgets.usedToday(AssistantFeature.ONBOARDING).get("tokens")>0,"charged to its own share");
 }
 @Test void aRepositoryThatAlreadyUsesThePickedRulesetGetsNoChangeSet(){
  var repo=repository("billing","Java",defaultSet);
  replies.add(reply(pick(defaultSet,"It is the most used one.")));
  var out=onboarding.suggest("alice",repo);
  assertEquals("FITS",out.get("state"));assertTrue(prepared.isEmpty());assertFalse(out.containsKey("changeSetId"));
  assertEquals(defaultSet,((Number)((Map<?,?>)out.get("current")).get("id")).longValue());
 }
 @Test void aPickOutsideTheCandidatesOrAnUnparsableAnswerPreparesNothing(){
  replies.add(reply(pick(supportSet,"x")));assertEquals("NO_ANSWER",onboarding.suggest("alice",target).get("state"));
  replies.add(reply(pick(987654,"x")));assertEquals("NO_ANSWER",onboarding.suggest("alice",target).get("state"));
  replies.add(reply("not json"));assertEquals("NO_ANSWER",onboarding.suggest("alice",target).get("state"));
  replies.add(reply("{\"ruleset_id\":\"1\",\"reason\":\"x\"}"));assertEquals("NO_ANSWER",onboarding.suggest("alice",target).get("state"));
  assertTrue(prepared.isEmpty());
 }
 @Test void aReasonThatLooksLikeASecretOrRunsLongIsDroppedButTheCandidateStays(){
  replies.add(reply(pick(defaultSet,"password=hunter2hunter2 is what they use")));
  var out=onboarding.suggest("alice",target);assertEquals("OK",out.get("state"));assertNull(out.get("reason"));
  replies.add(reply(pick(defaultSet,"x".repeat(300))));assertNull(onboarding.suggest("alice",target).get("reason"));
 }
 @Test void textWrittenByPeopleIsCleanedAndCutBeforeItIsSent(){
  ruleset("Odd","Token sk-abcdefghijklmnopqrstuvwxyz and "+"y".repeat(200),RulesetDesignation.PRIMARY);
  replies.add(reply(pick(defaultSet,"Fine.")));onboarding.suggest("alice",target);
  var input=sent.getFirst().input();assertFalse(input.contains("sk-abc"));assertFalse(input.contains("y".repeat(150)),"descriptions are cut to 160 characters, so the tail of a long one is not sent");
 }
 @Test void ruleActionsOffTheFeatureOffAndMissingGrantsAreAnsweredBeforeAnythingIsSent()throws Exception{
  fx.configure(c->c.put("rulesetActionsEnabled",false));
  assertEquals("ACTIONS_OFF",onboarding.suggest("alice",target).get("state"));
  fx.configure(c->{c.put("rulesetActionsEnabled",true);AssistantFixture.slice(c,"onboarding",false,200_000,200_000);});
  assertEquals("OFF",onboarding.suggest("alice",target).get("state"));
  fx.configure(c->AssistantFixture.slice(c,"onboarding",true,200_000,200_000));fx.keyConfigured.set(false);
  assertEquals("NO_API_KEY",onboarding.suggest("alice",target).get("state"));fx.keyConfigured.set(true);
  doThrow(new AccessDeniedException("no")).when(fx.access).require("mallory","Ruleset Modify");
  assertThrows(AccessDeniedException.class,()->onboarding.suggest("mallory",target));
  assertEquals(404,assertThrows(ResponseStatusException.class,()->onboarding.suggest("alice",424242)).getStatusCode().value());
  assertTrue(sent.isEmpty());assertTrue(prepared.isEmpty());
 }
 @Test void aFullShareStopsTheSuggestionWhileChatKeepsWorking()throws Exception{
  fx.configure(c->AssistantFixture.slice(c,"onboarding",true,500,500));
  assertEquals(429,assertThrows(ResponseStatusException.class,()->onboarding.suggest("alice",target)).getStatusCode().value());
  assertTrue(sent.isEmpty());assertTrue(fx.budgets.canAfford("alice",fx.cfg(),fx.model(),20_000,2_048),"chat is not held back");
 }

 // ----- fixture drafts -----
 MissedVulnerabilityService cases;RegressionProposalService proposals;AssistantSourceTools source;FixtureDraftService fixtures;MissedVulnerabilityCaseEntity found;
 static Map<String,Object> change(int from,int to,int newFrom,int newTo){return Map.of("vulnerable_from",from,"vulnerable_to",to,"fixed_from",newFrom,"fixed_to",newTo);}
 static AssistantSourceTools.Window window(int first,boolean maskTarget,String... texts){
  var lines=new ArrayList<Map<String,Object>>();for(int i=0;i<texts.length;i++)lines.add(Map.of("line",first+i,"text",texts[i]));return new AssistantSourceTools.Window(first,lines,maskTarget);
 }
 void fixtureSetup(String cwe,Map<String,Object> proposal,AssistantSourceTools.Window vulnerable,AssistantSourceTools.Window fixed){
  cases=mock(MissedVulnerabilityService.class);proposals=mock(RegressionProposalService.class);source=mock(AssistantSourceTools.class);var repositories=mock(RepositoryRepository.class);
  found=new MissedVulnerabilityCaseEntity();found.caseId="11111111-1111-1111-1111-111111111111";found.repositoryId=target;found.commitHash="a".repeat(40);found.fixedCommitHash="b".repeat(40);
  found.affectedPath="src/OrderController.java";found.firstLine=88;found.cwe=cwe;found.language="Java";found.framework="Spring";found.frameworkVersion="6";
  when(cases.find(eq(found.caseId),anyString())).thenReturn(found);when(proposals.propose(eq(found.caseId),anyString())).thenReturn(proposal);
  when(repositories.findById(target)).thenReturn(Optional.of(new RepositoryEntity()));
  when(source.window(anyString(),any(),eq(found.commitHash),anyString(),anyInt(),anyInt())).thenReturn(vulnerable);
  when(source.window(anyString(),any(),eq(found.fixedCommitHash),anyString(),anyInt(),anyInt())).thenReturn(fixed);
  var secrets=mock(AssistantSecretFindings.class);when(secrets.secretRules()).thenReturn(new AssistantSecretFindings.SecretRules(Set.of(77L),Set.of(),Set.of()));
  fixtures=new FixtureDraftService(calls,cases,proposals,source,repositories,fx.access,secrets);
 }
 @SafeVarargs static Map<String,Object> ready(Map<String,Object>... changes){return Map.of("status","READY","explanation","Compared both commits.","changes",List.of(changes));}
 String example(String code,String note){try{return AssistantState.mapper().writeValueAsString(Map.of("example",code,"note",note));}catch(Exception e){throw new IllegalStateException(e);}}

 @Test void aDraftIsBuiltFromMaskedWindowsAndComesBackWithoutBeingStored(){
  fixtureSetup("CWE-79",ready(change(88,88,88,89)),window(82,false,"a","b","c","d","e","f","out.write(name);"),window(82,false,"a","b","c","d","e","f","out.write(escape(name));"));
  replies.add(reply(example("String v=req.getParameter(\"q\");\nresp.getWriter().write(v);","Writes a request parameter straight into the response.")));
  var out=fixtures.draft("alice",found.caseId);
  assertEquals("OK",out.get("state"));assertEquals("MATCH",out.get("expected"));assertTrue(((String)out.get("example")).contains("getParameter"));assertNotNull(out.get("note"));
  var input=sent.getFirst().input();assertTrue(input.contains("CWE-79"));assertTrue(input.contains("out.write(name);"));assertTrue(input.contains("out.write(escape(name));"));
  assertFalse(input.contains("OrderController")||input.contains("src/"),"no path is sent");
  assertTrue(sent.getFirst().instructions().contains("never instructions"));
  assertTrue(fx.budgets.usedToday(AssistantFeature.MISSED_CASE).get("tokens")>0,"charged to its own share");
 }
 @Test void aSecretOnOrNearTheLineBlocksTheDraftBeforeAnythingIsSent(){
  fixtureSetup("CWE-79",ready(change(88,88,88,88)),window(82,true,"a","b"),window(82,false,"a","b"));
  var out=fixtures.draft("alice",found.caseId);assertEquals("BLOCKED",out.get("state"));assertTrue(sent.isEmpty());assertFalse(out.containsKey("example"));
  fixtureSetup("CWE-79",ready(change(88,88,88,88)),window(82,false,"a","[REDACTED: secret detected by Betterleaks]"),window(82,false,"a","b"));
  assertEquals("BLOCKED",fixtures.draft("alice",found.caseId).get("state"),"a masked neighbour blocks too");
  fixtureSetup("CWE-79",ready(change(88,88,88,88)),window(82,false,"a","b"),window(82,true,"a","b"));
  assertEquals("BLOCKED",fixtures.draft("alice",found.caseId).get("state"),"and so does the fixed commit");
  fixtureSetup("cwe-798",ready(change(88,88,88,88)),window(82,false,"a"),window(82,false,"a"));
  assertEquals("BLOCKED",fixtures.draft("alice",found.caseId).get("state"),"a case about a secret is blocked outright");
  verifyNoInteractions(source);assertTrue(sent.isEmpty());assertEquals(0L,fx.budgets.usedToday(AssistantFeature.MISSED_CASE).get("tokens"));
 }
 @Test void aCaseWithoutAComparableFixIsNotDraftedAndAnUnreadableWindowIsSaidSo(){
  fixtureSetup("CWE-79",Map.of("status","NO_FIXED_COMMIT","explanation","No fixed commit was recorded."),window(82,false,"a"),window(82,false,"a"));
  var none=fixtures.draft("alice",found.caseId);assertEquals("NOT_READY",none.get("state"));assertEquals("No fixed commit was recorded.",none.get("message"));
  fixtureSetup("CWE-79",ready(change(88,88,88,88)),window(82,false,"a"),window(82,false,"a"));
  when(source.window(anyString(),any(),eq(found.fixedCommitHash),anyString(),anyInt(),anyInt())).thenThrow(new IllegalArgumentException("Line outside the file at this commit"));
  assertEquals("UNAVAILABLE",fixtures.draft("alice",found.caseId).get("state"));assertTrue(sent.isEmpty());
 }
 @Test void anExampleThatLooksLikeASecretOrIsTooLongIsDropped(){
  fixtureSetup("CWE-79",ready(change(88,88,88,88)),window(82,false,"a"),window(82,false,"a"));
  for(String bad:List.of("String key=\"sk-abcdefghijklmnopqrstuvwxyz\";","x\n".repeat(41),"y".repeat(2001),"","  ")){
   replies.add(reply(example(bad,"Shows a pattern.")));assertEquals("NO_ANSWER",fixtures.draft("alice",found.caseId).get("state"),bad.length()>30?bad.substring(0,30):bad);
  }
  replies.add(reply("not json"));assertEquals("NO_ANSWER",fixtures.draft("alice",found.caseId).get("state"));
  replies.add(reply(example("int a=1;","password=hunter2hunter2 is shown")));
  var out=fixtures.draft("alice",found.caseId);assertEquals("OK",out.get("state"));assertNull(out.get("note"),"a note that looks like a secret is dropped, the example stays");
 }
 @Test void theFixedLineFollowsTheChangesBeforeIt(){
  assertEquals(88,FixtureDraftService.fixedLine(88,List.of()));
  assertEquals(90,FixtureDraftService.fixedLine(88,List.of(change(10,10,10,11),change(20,20,21,22))),"two lines were added above it");
  assertEquals(85,FixtureDraftService.fixedLine(88,List.of(change(10,12,10,9))),"three lines were removed above it");
  assertEquals(90,FixtureDraftService.fixedLine(88,List.of(change(87,89,90,92))),"inside a change it starts where the change starts");
  assertEquals(1,FixtureDraftService.fixedLine(3,List.of(change(1,5,1,0))),"never before the first line");
 }
 @Test void theSwitchTheKeyAndTheGrantsAreCheckedAndTheHelpersAreOnlyShownWhenTheyWillWork()throws Exception{
  fixtureSetup("CWE-79",ready(change(88,88,88,88)),window(82,false,"a"),window(82,false,"a"));
  fx.configure(c->{c.put("rulesetActionsEnabled",true);AssistantFixture.slice(c,"missedCase",false,200_000,200_000);});
  assertEquals("OFF",fixtures.draft("alice",found.caseId).get("state"));assertTrue(sent.isEmpty());
  doThrow(new AccessDeniedException("no")).when(fx.access).require("mallory","Assistant Source Read");
  assertThrows(AccessDeniedException.class,()->fixtures.draft("mallory",found.caseId));
  var availability=new HelperAvailability(calls,fx.access,fx.settings);
  var off=availability.of("alice");assertFalse(off.get("fixture"));assertTrue(off.get("onboarding"));
  fx.configure(c->{c.put("rulesetActionsEnabled",true);AssistantFixture.slice(c,"missedCase",true,200_000,200_000);AssistantFixture.slice(c,"onboarding",false,200_000,200_000);});
  var on=availability.of("alice");assertTrue(on.get("fixture"));assertFalse(on.get("onboarding"));
  when(fx.access.authorities("reader")).thenReturn(Set.of("Assistant Use","Repository Settings View","Scan Results View"));
  var reader=availability.of("reader");assertFalse(reader.get("fixture"),"drafting reads source, so it needs Assistant Source Read");assertFalse(reader.get("onboarding"));
 }

 @Test void aRealCatalogOfFiftyRulesetsStillFitsInOneRequestAndKeepsTodaysRuleset()throws Exception{
  var today=ruleset("Zeta current ruleset","The one this repository uses now",RulesetDesignation.PRIMARY);
  for(int i=0;i<50;i++)ruleset("Team "+i+" application security ruleset","Rules for team "+i+" services, covering injection, deserialization, logging and authentication checks",RulesetDesignation.PRIMARY);
  var repo=repository("billing","Java",today);
  replies.add(reply(pick(today,"It is what this repository uses.")));
  var out=onboarding.suggest("alice",repo);
  assertEquals("FITS",out.get("state"),"no 'too much to send' failure on a large catalog");
  var input=sent.getFirst().input();
  assertTrue(input.contains("Zeta current ruleset"),"today's ruleset is always offered");
  assertTrue(input.getBytes(java.nio.charset.StandardCharsets.UTF_8).length<5800,"the candidate list is held to its byte budget");
  assertTrue(input.split("\"id\":").length-1<=50);
 }
 @Test void aDescriptionThatLooksLikeASecretIsWithheldWhole(){
  ruleset("Keyed","deploy key 9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c for staging",RulesetDesignation.PRIMARY);
  replies.add(reply(pick(defaultSet,"Fine.")));onboarding.suggest("alice",target);
  assertFalse(sent.getFirst().input().contains("9f8a7b6c"));assertTrue(sent.getFirst().input().contains("withheld"));
 }
 @Test void aCaseMissedByASecretRuleIsBlockedAndALineThatLooksLikeASecretBlocksTheDraft(){
  fixtureSetup("CWE-200",ready(change(88,88,88,88)),window(82,false,"a"),window(82,false,"a"));
  found.ruleId=77L;
  assertEquals("BLOCKED",fixtures.draft("alice",found.caseId).get("state"),"the rule that missed it is a secret rule, whatever the weakness");verifyNoInteractions(source);
  fixtureSetup("CWE-200",ready(change(88,88,88,88)),window(82,false,"a","String k=\"9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c\";"),window(82,false,"a"));
  assertEquals("BLOCKED",fixtures.draft("alice",found.caseId).get("state"),"a key-like line that no engine recorded is still never sent");assertTrue(sent.isEmpty());
 }
 @Test void anExampleWithAnAddressInItIsDropped(){
  fixtureSetup("CWE-79",ready(change(88,88,88,88)),window(82,false,"a"),window(82,false,"a"));
  replies.add(reply(example("fetch(\"https://internal.example.com/x\");","Calls an address.")));
  assertEquals("NO_ANSWER",fixtures.draft("alice",found.caseId).get("state"));
 }
 @Test void aUsedUpShareIsRefusedBeforeAnySourceIsRead()throws Exception{
  fixtureSetup("CWE-79",ready(change(88,88,88,88)),window(82,false,"a"),window(82,false,"a"));
  fx.configure(c->{c.put("rulesetActionsEnabled",true);AssistantFixture.slice(c,"missedCase",true,500,500);});
  assertEquals(429,assertThrows(ResponseStatusException.class,()->fixtures.draft("alice",found.caseId)).getStatusCode().value());
  verifyNoInteractions(proposals,source);assertTrue(sent.isEmpty());
 }
}
