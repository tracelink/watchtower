package com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.mockito.*;
import com.tracelink.appsec.watchtower.core.job.*;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.*;
import com.tracelink.appsec.watchtower.core.scan.repository.*;
class BBWebhookManagementServiceTest {
 BBWebhookStore store;RepositoryRepository repos;BBWebhookManagementService service;BBCloudApi api;BBCloudIntegrationEntity bb;BBWebhookOperationEntity op;
 @BeforeEach void setup(){store=mock(BBWebhookStore.class);repos=mock(RepositoryRepository.class);api=mock(BBCloudApi.class);bb=mock(BBCloudIntegrationEntity.class);when(bb.createApi()).thenReturn(api);when(bb.getApiLabel()).thenReturn("bb");
  service=new BBWebhookManagementService(store,repos,mock(AsyncJobService.class),mock(AsyncJobRepository.class),"https://wt.example");
  op=new BBWebhookOperationEntity();op.id="op";op.workspace="team";when(bb.getWorkspace()).thenReturn("team");op.callbackHash=BBWebhookStore.hash("https://wt.example/rest/scan/bb");op.action="SYNC";op.actor="alice";op.preset="ALL";when(store.operation("op")).thenReturn(op);when(store.claim(eq("op"),any())).thenReturn(true);when(store.workerIntegration(eq("op"),any())).thenReturn(bb);
 }
 BBWebhookTaskEntity task(String scope){var t=new BBWebhookTaskEntity();t.id=scope;t.scope=scope;return t;}
 @Test void partialFailureDoesNotDiscardSuccessfulScopes(){var first=task("one");var second=task("two");when(store.pending("op")).thenReturn(List.of(first,second),List.of());when(api.listRepoHooks("one","https://wt.example")).thenReturn(List.of());when(api.listRepoHooks("two","https://wt.example")).thenThrow(new BBWebhookException(403,0));
  assertEquals("op",service.run("op",x->{}));verify(store).snapshot(eq("op"),any(),eq("one"),eq(List.of()),anyString(),eq("CHECKED"));verify(store).failure(eq("op"),any(),eq("two"),eq("MISSING_WEBHOOK_PERMISSION"),eq(false));verify(store).finish(eq("op"),any());}
 @Test void rateLimitKeepsTaskPendingAndUsesSeconds(){when(store.pending("op")).thenReturn(List.of(task("repo")));when(api.listRepoHooks("repo","https://wt.example")).thenThrow(new BBWebhookException(429,37));
  var ex=assertThrows(RetryLaterException.class,()->service.run("op",x->{}));assertEquals(37,ex.getDelaySeconds());verify(store).failure(eq("op"),any(),eq("repo"),eq("RATE_LIMITED"),eq(true));verify(store,never()).finish(any(),any());verify(store).release(eq("op"),any());}
 @Test void aStaleCheckStillShowsTheLastKnownWorkspaceHookInsteadOfNone(){
  var real=new BBCloudIntegrationEntity();real.setApiLabel("bb");real.setIntegrationId(8L);
  var hook=new com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudWebhook("u","wt.example/rest/scan/bb",List.of("repo:push"),true,true,true);
  // checked two days ago: stale, but still the last thing known
  when(store.scopeView(eq(8L),eq(""),anyString())).thenReturn(new BBWebhookStore.ScopeView("",List.of(hook),1L,1L,null,true,null,null));
  when(store.knownRepoCount(eq(8L),anyString())).thenReturn(0L);
  service.decorate(List.of(real));
  assertEquals(Boolean.TRUE,real.getCachedWorkspaceActive());
 }
 @Test void aWorkspaceThatWasNeverCheckedStaysUnknown(){
  var real=new BBCloudIntegrationEntity();real.setApiLabel("bb");real.setIntegrationId(8L);
  when(store.scopeView(eq(8L),eq(""),anyString())).thenReturn(new BBWebhookStore.ScopeView("",List.of(),null,null,null,true,null,null));
  when(store.knownRepoCount(eq(8L),anyString())).thenReturn(0L);
  service.decorate(List.of(real));
  assertNull(real.getCachedWorkspaceActive());
 }
 @Test void jobsBelongToOneIntegration(){when(store.integration("bb")).thenReturn(bb);when(bb.getIntegrationId()).thenReturn(8L);op.integrationId=9;
  assertThrows(IllegalArgumentException.class,()->service.operation("bb","op",0));}
 @Test void invalidSelectionNeverQueuesWork(){when(store.integration("bb")).thenReturn(bb);assertThrows(IllegalArgumentException.class,()->service.enqueue("bb","UPSERT",BBWebhookPreset.ALL,true,List.of("outside"),null,"alice"));verify(store,never()).create(any(),any(),any(),anyBoolean(),any(),any());}
}
