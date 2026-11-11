package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.env.Environment;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.alerting.*;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity;
import com.tracelink.appsec.watchtower.core.alerting.repository.*;
import com.tracelink.appsec.watchtower.core.assistant.alerts.*;
import com.tracelink.appsec.watchtower.core.assistant.alerts.AlertRouteActions.*;
import com.tracelink.appsec.watchtower.core.assistant.features.*;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/** S6: the alert copilot only drafts; a person applies it, and a route edited since the draft refuses it. */
class AssistantAlertCopilotTest {
 static final Set<String> GRANTS=Set.of("Assistant Use","Alert Settings View","Alert Settings Modify");
 @TempDir Path dir;AssistantFixture fx;StructuredFeatureCall calls;AlertSettingsService alerts;AlertRouteChangeSetService changes;AlertCopilotService copilot;
 final List<OpenAiLlmClient.Structured> sent=new ArrayList<>();final Deque<OpenAiLlmClient.StructuredReply> replies=new ArrayDeque<>();
 long platform,appsec,secretRoute,scannerRoute,reviewRoute;
 Runnable whileAsking;

 static OpenAiLlmClient.StructuredReply reply(String text){return new OpenAiLlmClient.StructuredReply(text,false,"completed",1200,60,true);}
 @BeforeEach void setup()throws Exception{
  fx=new AssistantFixture(dir,GRANTS);
  fx.configure(c->AssistantFixture.slice(c,"alertCopilot",true,200_000,200_000));
  fx.database.jdbc.update("INSERT INTO application_persistence_locks(lock_name) VALUES (?)","alert-route-configuration");
  // The ORM test schema adds a CHECK on the priority column that the real schema does not have.
  for(var name:fx.database.jdbc.queryForList("SELECT constraint_name FROM information_schema.table_constraints WHERE table_name='alert_routes' AND constraint_type='CHECK'",String.class))fx.database.jdbc.execute("ALTER TABLE alert_routes DROP CONSTRAINT \""+name+"\"");
  calls=new StructuredFeatureCall(fx.settings,R1Database.keys(fx.keyConfigured),fx.budgets,request->{sent.add(request);if(whileAsking!=null)whileAsking.run();return replies.poll();});
  var registry=new AlertTypeRegistry();registry.register("SECRET_DETECTED","A secret was found in a pull request",true);registry.register("SECRET_LIVE","A secret was confirmed working",false);
  alerts=new AlertSettingsService(fx.database.repository(AlertChannelRepository.class),fx.database.repository(AlertRouteRepository.class),fx.database.repository(AlertLogRepository.class),registry,mock(GoogleChatSender.class),EncryptionType.NONE,mock(Environment.class));
  changes=fx.database.service(new AlertRouteChangeSetService(fx.database.records,alerts,fx.access,fx.settings));
  copilot=new AlertCopilotService(calls,changes,alerts,fx.access);
  platform=channel("platform");appsec=channel("appsec");
  secretRoute=route("SECRET_DETECTED",platform,RulePriority.MEDIUM,AlertAggregation.PER_SCAN);
  scannerRoute=route("SCANNER_FAILURE",platform,null,AlertAggregation.PER_SCAN);
  reviewRoute=route("SCM_REVIEW_ACTION_FAILED",appsec,null,AlertAggregation.PER_FINDING);
 }
 @AfterEach void close(){fx.close();}

 long channel(String name){
  return new TransactionTemplate(fx.database.tx).execute(s->{var c=new AlertChannelEntity();c.setName(name);c.setWebhookUrl("https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t");fx.database.records.insert(c);return c.getId();});
 }
 long route(String type,long channel,RulePriority min,AlertAggregation aggregation){
  return new TransactionTemplate(fx.database.tx).execute(s->{var r=new AlertRouteEntity();r.setAlertType(type);r.setChannel(fx.database.records.find(AlertChannelEntity.class,channel));r.setMinPriority(min);
   r.setAggregation(aggregation);r.setDedupeWindowHours(720);r.setUpdatedAt(1);fx.database.records.insert(r);return r.getId();});
 }
 Map<String,Object> item(String action,Long routeId,String type,Long channel,String min,String aggregation,Integer hours,String include){
  var m=new LinkedHashMap<String,Object>();m.put("action",action);m.put("route_id",routeId);m.put("alert_type",type);m.put("channel_id",channel);m.put("min_priority",min);m.put("api_label_filter",null);
  m.put("repo_include",include);m.put("repo_exclude",null);m.put("aggregation",aggregation);m.put("dedupe_window_hours",hours);return m;
 }
 @SafeVarargs final String answer(Map<String,Object>... items){try{return AssistantState.mapper().writeValueAsString(Map.of("changes",List.of(items)));}catch(Exception e){throw new IllegalStateException(e);}}
 List<AlertRouteEntity> routes(){return alerts.getRoutes();}
 int drafts(){return fx.database.records.maps("SELECT c.id AS id FROM AlertRouteChangeSetEntity c",0,100).size();}
 Map<String,Object> threeChanges(){
  replies.add(reply(answer(item("ADD",null,"SECRET_LIVE",appsec,null,null,null,null),item("CHANGE",secretRoute,null,null,"HIGH",null,null,null),item("REMOVE",reviewRoute,null,null,null,null,null,null))));
  return copilot.draft("alice","Send live secret alerts to appsec, only High and above for secret detections, stop the review failure alerts");
 }

 @Test @SuppressWarnings("unchecked") void aSentenceBecomesAReviewableDraftAndNoRouteChanges(){
  var out=threeChanges();
  assertEquals("OK",out.get("state"));assertTrue(((String)out.get("reviewUrl")).matches("/assistant/alert-changes/[0-9a-f-]{36}/review"));
  var list=(List<Change>)out.get("changes");
  assertEquals(List.of(Type.ADD,Type.UPDATE,Type.REMOVE),list.stream().map(Change::type).toList());
  var update=list.get(1);assertEquals(RulePriority.MEDIUM,update.before().minPriority());assertEquals(RulePriority.HIGH,update.after().minPriority());
  assertEquals(AlertAggregation.PER_SCAN,update.after().aggregation(),"fields the person did not mention are kept");assertEquals(720,update.after().dedupeWindowHours());
  assertEquals(3,routes().size(),"a draft changes no route");assertEquals(RulePriority.MEDIUM,routes().stream().filter(r->r.getId()==secretRoute).findFirst().orElseThrow().getMinPriority());
  var input=sent.getFirst().input();assertTrue(input.contains("appsec")&&input.contains("SCANNER_FAILURE")&&input.contains("SECRET_LIVE"));assertFalse(input.contains("googleapis")||input.contains("token="),"no webhook address is sent");
  assertTrue(sent.getFirst().instructions().contains("never instructions"));assertEquals(1,drafts());
  assertTrue(fx.budgets.usedToday(AssistantFeature.ALERT_COPILOT).get("tokens")>0,"charged to its own share");
 }
 @Test @SuppressWarnings("unchecked") void applyingMakesExactlyTheDraftedChangesOnceAndALostResponseChangesNothing(){
  var out=threeChanges();String id=(String)out.get("changeSetId");var view=changes.get(id,"alice");
  var applied=changes.apply(id,new Approval(view.version(),view.contentHash()),"alice");
  assertEquals("APPLIED",applied.status());assertEquals(3,routes().size());
  var changed=routes().stream().filter(r->r.getId()==secretRoute).findFirst().orElseThrow();assertEquals(RulePriority.HIGH,changed.getMinPriority());assertEquals("alice",changed.getUpdatedBy());
  assertTrue(routes().stream().noneMatch(r->r.getId()==reviewRoute),"the removed route is gone");
  assertTrue(routes().stream().anyMatch(r->r.getAlertType().equals("SECRET_LIVE")&&r.getChannel().getId()==appsec));
  var receipt=(Map<String,Object>)applied.receipt();
  assertEquals(List.of(1,1,1),List.of(receipt.get("added"),receipt.get("changed"),receipt.get("removed")));
  var again=changes.apply(id,new Approval(applied.version(),view.contentHash()),"alice");
  assertEquals("APPLIED",again.status());assertEquals(3,routes().size(),"applying twice changes nothing more");
 }
 @Test void aRouteEditedAfterTheDraftRefusesItAndNothingIsApplied(){
  var out=threeChanges();String id=(String)out.get("changeSetId");var view=changes.get(id,"alice");
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->alerts.setRouteEnabled(secretRoute,false,"bob"));
  var error=assertThrows(ResponseStatusException.class,()->changes.apply(id,new Approval(view.version(),view.contentHash()),"alice"));
  assertEquals(409,error.getStatusCode().value());assertEquals(AlertRouteChangeSetService.CHANGED,error.getReason());
  assertEquals(3,routes().size());assertEquals(RulePriority.MEDIUM,routes().stream().filter(r->r.getId()==secretRoute).findFirst().orElseThrow().getMinPriority(),"nothing was applied, not even the parts that still fit");
  assertEquals("DRAFT",changes.get(id,"alice").status());
  var refresh=assertThrows(ResponseStatusException.class,()->changes.refresh(id,"alice"));
  assertEquals(409,refresh.getStatusCode().value(),"a draft made against an older route cannot be refreshed into the newer one, which could undo the edit");
  assertTrue(refresh.getReason().contains("Ask for the change again"));
  assertEquals("STALE_STATE",AlertRouteChangeSetController.conflictCode(AlertRouteChangeSetService.CHANGED));
  replies.add(reply(answer(item("CHANGE",secretRoute,null,null,"HIGH",null,null,null))));
  String fresh=(String)copilot.draft("alice","only High and above for secret detections").get("changeSetId");var v2=changes.get(fresh,"alice");
  assertEquals("APPLIED",changes.apply(fresh,new Approval(v2.version(),v2.contentHash()),"alice").status(),"asking again against the current route works");
  assertFalse(routes().stream().filter(r->r.getId()==secretRoute).findFirst().orElseThrow().isEnabled(),"the other person's edit was kept");
 }
 @Test void aRemovedRouteOrAnExpiredDraftIsRefused(){
  var out=threeChanges();String id=(String)out.get("changeSetId");var view=changes.get(id,"alice");
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->alerts.deleteRoute(reviewRoute,"bob"));
  assertEquals(409,assertThrows(ResponseStatusException.class,()->changes.apply(id,new Approval(view.version(),view.contentHash()),"alice")).getStatusCode().value());
  assertEquals(409,assertThrows(ResponseStatusException.class,()->changes.refresh(id,"alice")).getStatusCode().value(),"a draft for a route that is gone cannot be refreshed");
  replies.add(reply(answer(item("ADD",null,"SECRET_DETECTED",appsec,null,null,null,null))));
  String second=(String)copilot.draft("alice","Send secret alerts to appsec").get("changeSetId");var v2=changes.get(second,"alice");
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->{var row=fx.database.records.find(AlertRouteChangeSetEntity.class,second);row.expiresAt=1;});
  var expired=changes.get(second,"alice");
  assertEquals(410,assertThrows(ResponseStatusException.class,()->changes.apply(second,new Approval(expired.version(),v2.contentHash()),"alice")).getStatusCode().value());
 }
 @Test void onlyTheOwnerWithTheGrantsCanReadApplyOrCancelADraft(){
  var out=threeChanges();String id=(String)out.get("changeSetId");var view=changes.get(id,"alice");
  assertEquals(404,assertThrows(ResponseStatusException.class,()->changes.get(id,"bob")).getStatusCode().value(),"someone else's draft is not found");
  assertEquals(404,assertThrows(ResponseStatusException.class,()->changes.apply(id,new Approval(view.version(),view.contentHash()),"bob")).getStatusCode().value());
  doThrow(new AccessDeniedException("no")).when(fx.access).require("mallory","Alert Settings Modify");
  assertThrows(AccessDeniedException.class,()->copilot.draft("mallory","anything"));
  doThrow(new AccessDeniedException("no")).when(fx.access).require("alice","Alert Settings Modify");
  assertThrows(AccessDeniedException.class,()->changes.apply(id,new Approval(view.version(),view.contentHash()),"alice"),"the person applying needs the grant at that moment");
  doNothing().when(fx.access).require("alice","Alert Settings Modify");
  assertEquals(1,sent.size(),"nothing was sent for the person without the grant");assertEquals(3,routes().size());
  var canceled=changes.cancel(id,"alice");assertEquals("CANCELED",canceled.status());
  assertEquals(409,assertThrows(ResponseStatusException.class,()->changes.apply(id,new Approval(canceled.version(),canceled.contentHash()),"alice")).getStatusCode().value());
 }
 @Test void anAnswerThatNamesSomethingThatDoesNotExistIsDroppedWhole(){
  var add=item("ADD",null,"SECRET_DETECTED",appsec,null,null,null,null);
  for(String bad:List.of(
    answer(item("ADD",null,"SECRET_DETECTED",999L,null,null,null,null)),
    answer(item("ADD",null,"NO_SUCH_TYPE",appsec,null,null,null,null)),
    answer(item("CHANGE",999L,null,null,"HIGH",null,null,null)),
    answer(item("REMOVE",888L,null,null,null,null,null,null)),
    answer(item("CHANGE",scannerRoute,null,null,"HIGH",null,null,null),item("REMOVE",scannerRoute,null,null,null,null,null,null)),
    answer(item("DELETE_CHANNEL",null,null,null,null,null,null,null)),
    answer(item("ADD",null,"SECRET_DETECTED",null,null,null,null,null)),
    answer(add,add,add,add,add,add),
    "not json")){
   replies.add(reply(bad));assertEquals("NO_ANSWER",copilot.draft("alice","change something").get("state"),bad);
  }
  assertEquals(0,drafts());assertEquals(3,routes().size());
 }
 @Test void aChangeThatLeavesARouteAsItIsOrAnExistingRouteIsNotDrafted(){
  replies.add(reply(answer(item("CHANGE",secretRoute,null,null,"MEDIUM",null,null,null),item("ADD",null,"SECRET_DETECTED",platform,"MEDIUM","PER_SCAN",720,null))));
  assertEquals("NOTHING",copilot.draft("alice","make sure those exist").get("state"));assertEquals(0,drafts());
  replies.add(reply(answer()));assertEquals("NOTHING",copilot.draft("alice","nothing to do").get("state"));
 }
 @Test @SuppressWarnings("unchecked") void NONEClearsAFilterAndAnInvalidFilterIsSaidSoWithoutADraft(){
  replies.add(reply(answer(item("CHANGE",secretRoute,null,null,"NONE",null,null,null))));
  var out=copilot.draft("alice","remove the priority filter from secret detections");
  assertNull(((List<Change>)out.get("changes")).getFirst().after().minPriority(),"NONE clears it");
  replies.add(reply(answer(item("ADD",null,"SECRET_DETECTED",appsec,null,null,null,"bad filter!!"))));
  var invalid=copilot.draft("alice","only some repos");assertEquals("INVALID",invalid.get("state"));assertTrue(((String)invalid.get("message")).contains("letters"));
  assertEquals(1,drafts());
 }
 @Test void textThatLooksLikeASecretOrAWebhookAddressIsNeverSent(){
  for(String bad:List.of("Send alerts to https://chat.googleapis.com/v1/spaces/AAAA/messages?key=AIzaSyabc&token=xyz","use hooks.slack.com for it","the key is sk-abcdefghijklmnopqrstuvwxyz","password=hunter2hunter2 please")){
   var out=copilot.draft("alice",bad);assertEquals("REFUSED_SECRET",out.get("state"),bad);
  }
  assertTrue(sent.isEmpty());assertThrows(IllegalArgumentException.class,()->copilot.draft("alice","   "));assertThrows(IllegalArgumentException.class,()->copilot.draft("alice","x".repeat(501)));
 }
 @Test void theSwitchTheKeyTheBudgetAndALargeRouteListAreAnsweredBeforeAnythingIsDrafted()throws Exception{
  fx.configure(c->AssistantFixture.slice(c,"alertCopilot",false,200_000,200_000));
  assertEquals("OFF",copilot.draft("alice","anything").get("state"));
  fx.configure(c->AssistantFixture.slice(c,"alertCopilot",true,200_000,200_000));fx.keyConfigured.set(false);
  assertEquals("NO_API_KEY",copilot.draft("alice","anything").get("state"));fx.keyConfigured.set(true);
  fx.configure(c->AssistantFixture.slice(c,"alertCopilot",true,500,500));
  assertEquals(429,assertThrows(ResponseStatusException.class,()->copilot.draft("alice","anything")).getStatusCode().value());
  fx.configure(c->AssistantFixture.slice(c,"alertCopilot",true,200_000,200_000));
  for(int i=0;i<80;i++)route("SCANNER_FAILURE",platform,RulePriority.LOW,AlertAggregation.PER_FINDING);
  assertEquals("TOO_LARGE",copilot.draft("alice","anything").get("state"));
  assertTrue(sent.isEmpty());assertEquals(0,drafts());
 }
 @Test void theHelperIsOnlyShownToSomeoneWhoCanChangeRoutesWhenItWillWork()throws Exception{
  var availability=new HelperAvailability(calls,fx.access,fx.settings);
  assertTrue(availability.of("alice").get("alerts"));
  when(fx.access.authorities("viewer")).thenReturn(Set.of("Assistant Use","Alert Settings View"));
  assertFalse(availability.of("viewer").get("alerts"),"changing routes needs Alert Settings Modify");
  fx.configure(c->AssistantFixture.slice(c,"alertCopilot",false,200_000,200_000));
  assertFalse(availability.of("alice").get("alerts"));
 }

 @Test void aRouteEditedWhileTheAssistantWasWorkingIsNotDraftedOverTheEdit(){
  whileAsking=()->new TransactionTemplate(fx.database.tx).executeWithoutResult(s->alerts.updateRoute(secretRoute,new AlertSettingsService.RouteRequest("SECRET_DETECTED",platform,RulePriority.HIGH,null,null,null,AlertAggregation.PER_SCAN,24),"bob"));
  replies.add(reply(answer(item("CHANGE",secretRoute,null,platform==appsec?null:appsec,null,null,null,null))));
  var out=copilot.draft("alice","move secret detections to appsec");
  assertEquals("INVALID",out.get("state"));assertEquals("A route was edited while the assistant was working. Ask again.",out.get("message"));
  assertEquals(0,drafts());var kept=routes().stream().filter(r->r.getId()==secretRoute).findFirst().orElseThrow();
  assertEquals(24,kept.getDedupeWindowHours());assertEquals(RulePriority.HIGH,kept.getMinPriority());
 }
 @Test void theSameAdditionTwiceOrAnAdditionAnEditAlreadyMakesIsOneRoute(){
  var add=item("ADD",null,"SECRET_LIVE",appsec,null,null,null,null);
  replies.add(reply(answer(add,add)));
  @SuppressWarnings("unchecked") var out=(List<Change>)copilot.draft("alice","send live secrets to appsec").get("changes");
  assertEquals(1,out.size());
  replies.add(reply(answer(item("CHANGE",scannerRoute,"SECRET_LIVE",appsec,null,null,720,null),item("ADD",null,"SECRET_LIVE",appsec,null,"PER_SCAN",720,null))));
  @SuppressWarnings("unchecked") var result=(List<Change>)copilot.draft("alice","change scanner failures to live secrets and add live secrets").get("changes");
  assertEquals(List.of(Type.UPDATE),result.stream().map(Change::type).toList(),"the addition equals what the edit produces");
 }
 @Test void aDisabledChannelIsNotOfferedAndAnAnswerThatPicksItIsDropped(){
  long off=channel("quiet");
  new TransactionTemplate(fx.database.tx).executeWithoutResult(s->alerts.updateChannel(off,"quiet","",false,"admin"));
  replies.add(reply(answer(item("ADD",null,"SECRET_LIVE",off,null,null,null,null))));
  assertEquals("NO_ANSWER",copilot.draft("alice","send live secrets to quiet").get("state"));
  assertTrue(sent.getFirst().input().contains("quiet"),"the model is told the channel is disabled");
  assertEquals(0,drafts());
 }
 @Test void turningTheFeatureOffStopsADraftFromBeingAppliedOrExtendedButNotCanceled()throws Exception{
  var out=threeChanges();String id=(String)out.get("changeSetId");var view=changes.get(id,"alice");
  fx.configure(c->AssistantFixture.slice(c,"alertCopilot",false,200_000,200_000));
  assertEquals(503,assertThrows(ResponseStatusException.class,()->changes.apply(id,new Approval(view.version(),view.contentHash()),"alice")).getStatusCode().value());
  assertEquals(503,assertThrows(ResponseStatusException.class,()->changes.refresh(id,"alice")).getStatusCode().value());
  assertEquals(3,routes().size());assertEquals("DRAFT",changes.get(id,"alice").status(),"it can still be read");
  assertEquals("CANCELED",changes.cancel(id,"alice").status(),"and canceled");
 }
 @Test void aRefusalSaysWhyAndNamesNoOneElse(){
  assertEquals("CANCELED",AlertRouteChangeSetController.conflictCode("This draft is canceled"));
  assertEquals("NOT_PENDING",AlertRouteChangeSetController.conflictCode("Only a pending draft can be refreshed"));
  assertEquals("CONFLICT",AlertRouteChangeSetController.conflictCode("The change set changed; review its current preview"));
  var controller=new AlertRouteChangeSetController(changes);
  var body=(Map<?,?>)controller.status(new ResponseStatusException(org.springframework.http.HttpStatus.GONE,"Approval expired")).getBody();assertEquals("APPROVAL_EXPIRED",body.get("code"));
  assertEquals("STALE_STATE",((Map<?,?>)controller.stale().getBody()).get("code"));
  assertEquals("Invalid",((Map<?,?>)controller.invalid(new IllegalArgumentException("Invalid")).getBody()).get("error"));
 }

 @Test void theReviewPageOpensOnlyForThePersonWhoHasTheDraft(){
  var out=threeChanges();String id=(String)out.get("changeSetId");
  var page=new AlertRouteChangeSetPageController(changes);
  var alice=mock(org.springframework.security.core.Authentication.class);when(alice.getName()).thenReturn("alice");
  var view=page.review(id,alice);
  assertEquals("assistant/alert-change-set",view.getModel().get(com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView.CONTENT_VIEW_NAME));
  assertEquals(id,view.getModel().get("changeSetId"));
  var bob=mock(org.springframework.security.core.Authentication.class);when(bob.getName()).thenReturn("bob");
  assertEquals(404,assertThrows(ResponseStatusException.class,()->page.review(id,bob)).getStatusCode().value(),"someone else's draft has no page");
  assertThrows(IllegalArgumentException.class,()->page.review("not-an-id",alice));
 }
}
