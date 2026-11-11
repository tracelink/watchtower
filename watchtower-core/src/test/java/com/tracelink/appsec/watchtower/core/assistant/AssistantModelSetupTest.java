package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import com.fasterxml.jackson.databind.node.*;

/** Synthetic provider qualification must work before Chat activation and must never enable it. */
class AssistantModelSetupTest {
 R1Database d;AssistantSettingsService settings;AssistantAccess access;OpenAiLlmClient client;AssistantModelSetup setup;
 @BeforeEach void init()throws Exception {
  d=new R1Database();access=mock(AssistantAccess.class);client=mock(OpenAiLlmClient.class);settings=d.service(new AssistantSettingsService(d.records,R1Database.keys(new java.util.concurrent.atomic.AtomicBoolean(true)),null,false));
  setup=new AssistantModelSetup(settings,access,d.service(new AssistantBudgetService(d.records,d.tx)),client);when(client.discover()).thenReturn(List.of("fixture-model"));
  AtomicInteger count=new AtomicInteger();when(client.complete(any())).thenAnswer(inv->{LlmClient.Request req=inv.getArgument(0);assertEquals("r1-v1",req.promptVersion());assertFalse(req.input().toString().contains("rule_id"));var items=AssistantState.mapper().createArrayNode();
   if(count.getAndIncrement()==0)items.addObject().put("type","function_call").put("name","read_compatibility_marker").put("call_id","probe_1").put("arguments","{}");
   else {assertTrue(req.input().toString().contains("function_call_output"));items.addObject().put("type","message").putArray("content").addObject().put("type","output_text").put("text","WATCHTOWER_SYNTHETIC_OK");}
   return new LlmClient.Response(items,"completed",100,100,true);
  });when(client.structured(any())).thenReturn(new OpenAiLlmClient.StructuredReply("{\"ok\":true}",false,"completed",100,100,true));
 }
 @AfterEach void close(){d.close();}
 AssistantModelSetup.Configure request(){return new AssistantModelSetup.Configure(settings.get().version(),"fixture-model","low",24000,8192,750000,4500000);}
 @Test void approvesOnlyAfterToolReplayAndStructuredChecksWhileChatStaysOff()throws Exception {
  assertFalse(settings.get().settings().enabled());setup.configure(request(),"admin");var cfg=settings.get().settings();assertFalse(cfg.enabled());assertFalse(cfg.rulesetActionsEnabled());assertEquals("fixture-model",cfg.defaultModel());assertEquals(List.of("low"),cfg.allowedModels().getFirst().efforts());assertEquals("responses-synthetic-setup-v1",cfg.allowedModels().getFirst().validationRef());verify(client,times(2)).complete(any());verify(client).structured(any());
 }
 @Test void failedProtocolAndRevokedAccessNeverApprove()throws Exception {
  when(client.structured(any())).thenReturn(new OpenAiLlmClient.StructuredReply("{}",false,"completed",100,100,true));assertThrows(org.springframework.web.server.ResponseStatusException.class,()->setup.configure(request(),"admin"));assertTrue(settings.get().settings().allowedModels().isEmpty());
  doThrow(new org.springframework.security.access.AccessDeniedException("revoked")).when(access).require("admin","Assistant Admin");clearInvocations(client);assertThrows(org.springframework.security.access.AccessDeniedException.class,()->setup.configure(request(),"admin"));verifyNoInteractions(client);
 }
 @Test void staleAndOverBudgetConfigurationDoesNotCallProvider(){
  var old=request();settings.save(new AssistantSettingsService.Versioned(settings.get().version(),settings.get().settings()),"other");assertThrows(org.springframework.web.server.ResponseStatusException.class,()->setup.configure(old,"admin"));
  assertThrows(IllegalArgumentException.class,()->setup.configure(new AssistantModelSetup.Configure(settings.get().version(),"fixture-model","low",999999,8192,1000000000,1000000000),"admin"));verifyNoInteractions(client);
 }
}
