package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.*;
import com.tracelink.appsec.watchtower.core.encryption.service.DataEncryptionService;

/** Ordinary ORM behavior tests. Schema is generated from entities; no migration scripts run. */
@SpringBootTest(classes=WatchtowerTestApplication.class,properties={"spring.flyway.enabled=false","spring.jpa.hibernate.ddl-auto=create-drop","spring.datasource.url=jdbc:h2:mem:webhookstore;MODE=MySQL;DB_CLOSE_DELAY=-1","watchtower.publicUrl=https://wt.example","watchtower.bootstrap-admin-password=WebhookTestsOnly-52bG4r!"})
class BBWebhookStoreTest {
 @Autowired BBWebhookStore store;
 @Autowired ApiIntegrationRepository integrations;
 @Autowired com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRCommentDeliveryClaims claims;
 @MockitoBean DataEncryptionService encryption;
 private BBCloudIntegrationEntity bb;
 @BeforeEach void setup(){
  when(encryption.encryptString(any(),any())).thenAnswer(i->i.getArgument(0));
  when(encryption.decryptString(any(),any())).thenAnswer(i->i.getArgument(0));
  bb=new BBCloudIntegrationEntity();bb.setApiLabel("test"+UUID.randomUUID().toString().replace("-",""));bb.setWorkspace("team");bb.setRejectOption(BBCloudRejectOption.DO_NOTHING);bb.setWebhookSecret("old-secret");bb=integrations.saveAndFlush(bb);
 }
 private BBWebhookOperationEntity op(String action,String...scopes){var selected=new TreeMap<String,String>();for(String s:scopes)selected.put(s,null);return store.create(bb.getApiLabel(),action,BBWebhookPreset.ALL,true,"alice",selected);}
 private BBCloudWebhook hook(){return new BBCloudWebhook("uuid","wt.example/rest/scan/test",List.of("pullrequest:created"),true,true,true);}
 @Test void snapshotsCommitPerScopeAndFailuresKeepTheLastGoodResult(){
  var op=op("SYNC","","repo");assertTrue(store.claim(op.id,"one"));
  var tasks=store.pending(op.id);var workspace=tasks.stream().filter(t->t.scope.isEmpty()).findFirst().orElseThrow();var repo=tasks.stream().filter(t->!t.scope.isEmpty()).findFirst().orElseThrow();
  store.snapshot(op.id,"one",workspace.id,List.of(hook()),"hash","CHECKED");store.snapshot(op.id,"one",repo.id,List.of(hook()),"hash","CHECKED");store.finish(op.id,"one");store.release(op.id,"one");
  var refresh=op("SYNC","repo");store.claim(refresh.id,"two");var task=store.pending(refresh.id).getFirst();
  store.failure(refresh.id,"two",task.id,"MISSING_WEBHOOK_PERMISSION",false);store.finish(refresh.id,"two");store.release(refresh.id,"two");
  var scope=store.scopeView(bb.getIntegrationId(),"repo","hash");assertEquals(1,scope.hooks().size());assertNotNull(scope.checkedAt());assertEquals("MISSING_WEBHOOK_PERMISSION",scope.error());
  assertEquals("PARTIAL_FAILURE",store.operationView(refresh.id,0).status());
  store.retry(refresh.id);assertEquals(1,store.pending(refresh.id).size());
  assertEquals(1,store.scopes(bb.getIntegrationId(),"",0,"hash").size(),"workspace is never in repository results");
 }
 @Test void leaseExcludesOtherWorkersAndReleasedWorkersCannotPublishSnapshots(){
  var op=op("SYNC","repo");assertTrue(store.claim(op.id,"one"));assertFalse(store.claim(op.id,"two"));var task=store.pending(op.id).getFirst();
  store.release(op.id,"one");assertTrue(store.claim(op.id,"two"));
  assertThrows(IllegalStateException.class,()->store.snapshot(op.id,"one",task.id,List.of(hook()),"hash","CHECKED"));
  store.snapshot(op.id,"two",task.id,List.of(),"hash","CHECKED");store.finish(op.id,"two");store.release(op.id,"two");
  assertNotNull(store.scopeView(bb.getIntegrationId(),"repo","hash").checkedAt(),"an empty successful scope remains distinguishable from never checked");
 }
 @Test void rotationKeepsBothSignaturesAndResumesTheSameNewSecret(){
  var op=op("ROTATE","repo");store.claim(op.id,"one");store.beginRotation(op.id,"one");var current=store.workerIntegration(op.id,"one");String next=current.getWebhookSecret();
  assertNotEquals("old-secret",next);byte[] payload="{}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
  assertTrue(current.isWebhookSignatureValid(payload,BBWebhookSignature.headerValueFor("old-secret",payload)));
  assertTrue(current.isWebhookSignatureValid(payload,BBWebhookSignature.headerValueFor(next,payload)));
  var task=store.pending(op.id).getFirst();store.failure(op.id,"one",task.id,"ERROR",false);store.finish(op.id,"one");store.release(op.id,"one");
  assertTrue(store.rotation(bb.getIntegrationId()).pending());assertThrows(IllegalStateException.class,()->op("UPSERT","repo"));
  store.retry(op.id);store.claim(op.id,"two");store.beginRotation(op.id,"two");assertEquals(next,store.workerIntegration(op.id,"two").getWebhookSecret());
  store.snapshot(op.id,"two",task.id,List.of(hook()),"hash","ROTATED");store.finish(op.id,"two");store.release(op.id,"two");assertFalse(store.rotation(bb.getIntegrationId()).pending());
  assertTrue(store.rotation(bb.getIntegrationId()).previousAcceptedUntil()<System.currentTimeMillis()+700000);
 }
 // A refused change (foreign hook, hook limit, changed settings) is the task's outcome; the saved snapshot of the repository is
 // still good and must not be shown as a failed read on every hook of that repository.
 @Test void aRefusedChangeFailsTheTaskButNotTheSavedSnapshot(){
  var sync=op("SYNC","repo");store.claim(sync.id,"one");store.snapshot(sync.id,"one",store.pending(sync.id).getFirst().id,List.of(hook()),"hash","CHECKED");store.finish(sync.id,"one");store.release(sync.id,"one");
  for(String refused:List.of("SELECTION_OR_OWNERSHIP_CHANGED","CONFIGURATION_CHANGED","LIMIT")){
   var change=op("UPSERT","repo");store.claim(change.id,"two");var task=store.pending(change.id).getFirst();
   store.failure(change.id,"two",task.id,refused,false);store.finish(change.id,"two");store.release(change.id,"two");
   assertNull(store.scopeView(bb.getIntegrationId(),"repo","hash").error(),refused+" is not a failed read");
   assertEquals("PARTIAL_FAILURE",store.operationView(change.id,0).status(),"the task still reports the refusal");
   assertEquals(refused,store.operationView(change.id,0).tasks().getFirst().result());
  }
  var read=op("SYNC","repo");store.claim(read.id,"three");store.failure(read.id,"three",store.pending(read.id).getFirst().id,"MISSING_WEBHOOK_PERMISSION",false);store.finish(read.id,"three");store.release(read.id,"three");
  assertEquals("MISSING_WEBHOOK_PERMISSION",store.scopeView(bb.getIntegrationId(),"repo","hash").error(),"a provider failure still marks the scope");
 }
 @Test void callbackChangesInvalidateCachedOwnership(){var op=op("SYNC","repo");store.claim(op.id,"one");store.snapshot(op.id,"one",store.pending(op.id).getFirst().id,List.of(hook()),"old","CHECKED");
  var scope=store.scopeView(bb.getIntegrationId(),"repo","new");assertTrue(scope.stale());assertFalse(scope.hooks().getFirst().owned());store.finish(op.id,"one");store.release(op.id,"one");}
 @Test void commentReservationsSuppressAcrossWorkersAndReleaseOnlyTheirOwner() {
  String label=bb.getApiLabel();var first=claims.claim(label,"repo","1",9);assertNotNull(first);
  assertNull(claims.claim(label,"repo","1",9));
  claims.release(new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRCommentDeliveryClaims.Claim(first.id(),"wrong"));
  assertNull(claims.claim(label,"repo","1",9));claims.release(first);assertNotNull(claims.claim(label,"repo","1",9));
  assertNotNull(claims.claim(label,"other-repo","1",9));
 }

}
