package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.tracelink.appsec.watchtower.core.assistant.context.*;

/** S1b: a person may share the rule draft they are typing, for one turn, redacted, size-capped and never kept in the page card. */
class AssistantDraftShareTest {
 @TempDir Path dir;AssistantFixture fx;DraftShare drafts;
 @BeforeEach void setup()throws Exception{
  fx=new AssistantFixture(dir,Set.of("Assistant Use","Ruleset View"));
  fx.configure(c->c.putObject("features").putObject("enabled").put("contextCards",true));
  drafts=new DraftShare(fx.settings);
 }
 @AfterEach void close(){fx.close();}
 AssistantTurnRunner runner(LlmClient client){return new AssistantTurnRunner(fx.db,fx.settings,fx.tools,client,fx.budgets);}

 @Test void aPlainDraftIsAcceptedAsItIs(){
  assertEquals("<rule name=\"x\"><properties><property name=\"xpath\" value=\"//Foo\"/></properties></rule>",drafts.accept("<rule name=\"x\"><properties><property name=\"xpath\" value=\"//Foo\"/></properties></rule>"));
  assertEquals("(?i)foo\\s*=\\s*bar",drafts.accept("  (?i)foo\\s*=\\s*bar  "),"surrounding space is trimmed");
 }
 @Test void aDraftThatLooksLikeASecretIsRefusedNotJustMasked(){
  for(String secret:List.of("password = hunter2hunter2","key sk-abcdefghijklmnopqrstuvwxyz","-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----","token: ghp_abcdefghijklmnopqrstuvwxyz0123","AKIAABCDEFGHIJKLMNOP","aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5hI7jK9m"))
   assertEquals("This draft looks like it contains a secret, so it was not shared. Remove it and try again.",assertThrows(IllegalArgumentException.class,()->drafts.accept("rule text "+secret)).getMessage(),secret);
 }
 @Test void aDraftWithATokenOrACredentialUrlIsRefusedToo(){
  for(String secret:List.of("call with Bearer abcdefghijklmnopqrstuvwxyz0123","jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig","xoxb-1234567890-abcdefghij","https://deploy:hunter2secret@git.example.com/x.git"))
   assertThrows(IllegalArgumentException.class,()->drafts.accept("rule "+secret),secret);
 }
 @Test void emptyOrOversizedDraftsAreRefusedWithPlainReasons(){
  assertThrows(IllegalArgumentException.class,()->drafts.accept("   "));
  var e=assertThrows(IllegalArgumentException.class,()->drafts.accept("a ".repeat(DraftShare.MAX_CHARS)));
  assertTrue(e.getMessage().contains("too long"));
  assertDoesNotThrow(()->drafts.accept("a ".repeat(DraftShare.MAX_CHARS/2)));
 }
 @Test void aRefusalReachesThePersonInItsOwnWordsNotAsAGenericError(){
  var refused=assertThrows(DraftShare.Refused.class,()->drafts.accept("rule password = hunter2hunter2"));
  var response=new AssistantApiErrors().draftRefused(refused);
  assertEquals(400,response.getStatusCode().value());
  assertEquals(Map.of("error","This draft looks like it contains a secret, so it was not shared. Remove it and try again."),response.getBody());
 }
 @Test void sharingNeedsPageContextToBeOn()throws Exception{
  fx.configure(c->c.putObject("features").putObject("enabled").put("contextCards",false));
  assertTrue(assertThrows(IllegalArgumentException.class,()->drafts.accept("rule text")).getMessage().contains("turned off"));
 }
 @Test void theDraftReachesTheModelOnceAsUntrustedTextAndIsGoneFromTheNextTurn()throws Exception{
  var first=fx.db.submit(new AssistantPersistence.Submit(null,UUID.randomUUID().toString(),"Why does my rule miss foo?",null,null),"alice",null,drafts.accept("(?i)fooo\\s*=\\s*bar"));
  var seen=new ArrayList<String>();
  runner(request->{seen.add(request.input().toString());return AssistantFixture.answer("Your pattern has a typo in the first word.");}).run(fx.db.claim(first.id(),"pod-a").orElseThrow());
  assertEquals(1,seen.size());assertTrue(seen.getFirst().contains("fooo"));assertTrue(seen.getFirst().contains("untrusted"));assertTrue(seen.getFirst().contains(AssistantState.DRAFT_PREFIX.substring(0,30)));
  var state=fx.db.state(fx.db.turn(first.id()));
  assertFalse(state.protocol.toString().contains("fooo"),"the draft leaves the conversation once the answer is given");
  assertNull(state.context,"it was never part of the page card");
  var second=fx.db.submit(new AssistantPersistence.Submit(first.session(),UUID.randomUUID().toString(),"And how do I fix it?",null,null),"alice");
  var later=new ArrayList<String>();
  runner(request->{later.add(request.input().toString());return AssistantFixture.answer("Fix the typo.");}).run(fx.db.claim(second.id(),"pod-a").orElseThrow());
  assertFalse(later.getFirst().contains("fooo"),"one turn only");
 }
 @Test void aNewDraftReplacesAnEarlierOneAndTheCardIsNeverMixedWithIt()throws Exception{
  var state=new AssistantState();state.user("one");
  state.useDraft("first draft");state.useDraft("second draft");
  assertEquals(2,state.protocol.size());assertFalse(state.protocol.toString().contains("first draft"));assertTrue(state.protocol.toString().contains("second draft"));
  state.useContext(ContextCard.blocked("finding",Map.of("scanId",1)));
  assertTrue(state.protocol.toString().contains("second draft"),"changing the page does not drop the draft the person shared");
  state.user("two");
  assertFalse(state.protocol.toString().contains("second draft"));
 }
 @Test void theSameKeyWithADifferentDraftIsAConflict()throws Exception{
  String key=UUID.randomUUID().toString();
  fx.db.submit(new AssistantPersistence.Submit(null,key,"Why?",null,null),"alice",null,"draft one");
  assertThrows(org.springframework.web.server.ResponseStatusException.class,()->fx.db.submit(new AssistantPersistence.Submit(null,key,"Why?",null,null),"alice",null,"draft two"));
  assertDoesNotThrow(()->fx.db.submit(new AssistantPersistence.Submit(null,key,"Why?",null,null),"alice",null,"draft one"));
 }
}
