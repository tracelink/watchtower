package com.tracelink.appsec.watchtower.core.scan.apiintegration;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.*;
@SpringBootTest(classes=WatchtowerTestApplication.class)
@AutoConfigureMockMvc
class BitbucketWebhookControllerTest {
 @Autowired MockMvc mvc;
 @MockitoBean BBWebhookManagementService service;
 @Test @WithMockUser(authorities=CorePrivilege.API_SETTINGS_VIEW_NAME)
 void readsStoredWorkspaceSeparatelyFromRepositories()throws Exception{
  var workspace=new BBWebhookStore.ScopeView("",List.of(new BBCloudWebhook("id","wt.example/hook",List.of("pullrequest:created"),true,true,true)),1L,1L,null,false,"alice",1L);
  when(service.inventory("bb","",0)).thenReturn(new BBWebhookManagementService.Inventory("bb",workspace,List.of(),0,0,0,new BBWebhookStore.RotationView(false,null,null),List.of()));
  mvc.perform(get("/apisettings/bb/webhooks")).andExpect(status().isOk()).andExpect(header().string("Cache-Control","no-store"))
   .andExpect(jsonPath("$.workspace.hooks[0].owned").value(true)).andExpect(jsonPath("$.workspace.hooks[0].secret").doesNotExist()).andExpect(jsonPath("$.repositories").isEmpty());
 }
 @Test @WithMockUser(authorities=CorePrivilege.API_SETTINGS_VIEW_NAME)
 void viewerCanRefreshButCannotWriteHooks()throws Exception{
  when(service.refresh("bb",null,false,"user")).thenReturn("operation");
  mvc.perform(post("/apisettings/bb/webhooks/refresh").with(SecurityMockMvcRequestPostProcessors.csrf()).contentType("application/json").content("{}"))
   .andExpect(status().isAccepted()).andExpect(jsonPath("$.operationId").value("operation"));
  mvc.perform(put("/apisettings/bb/webhooks/workspace").with(SecurityMockMvcRequestPostProcessors.csrf()).contentType("application/json").content("{\"preset\":\"ALL\",\"active\":true}"))
   .andExpect(status().isForbidden());
  verify(service,never()).enqueue(anyString(),anyString(),any(),anyBoolean(),any(),any(),anyString());
 }
 @Test @WithMockUser(authorities={CorePrivilege.API_SETTINGS_VIEW_NAME,CorePrivilege.API_SETTINGS_MODIFY_NAME})
 void modifierCanManageReposButCsrfAndRotationConfirmationAreRequired()throws Exception{
  when(service.enqueue(eq("bb"),eq("UPSERT"),eq(BBWebhookPreset.ALL),eq(true),eq(List.of("repo")),isNull(),eq("user"))).thenReturn("operation");
  mvc.perform(post("/apisettings/bb/webhooks/repos").contentType("application/json").content("{\"repositories\":[\"repo\"],\"preset\":\"ALL\",\"active\":true}"))
   .andExpect(status().isForbidden());
  mvc.perform(post("/apisettings/bb/webhooks/repos").with(SecurityMockMvcRequestPostProcessors.csrf()).contentType("application/json").content("{\"repositories\":[\"repo\"],\"preset\":\"ALL\",\"active\":true}"))
   .andExpect(status().isAccepted());
  mvc.perform(post("/apisettings/bb/webhooks/rotate-secret").with(SecurityMockMvcRequestPostProcessors.csrf()).contentType("application/json").content("{\"confirmLabel\":\"wrong\"}"))
   .andExpect(status().isBadRequest());
 }
 @Test @WithMockUser(authorities=CorePrivilege.REPO_SETTINGS_VIEW_NAME)
 void repositoryPrivilegeDoesNotGrantWebhookAccess()throws Exception{mvc.perform(get("/apisettings/bb/webhooks")).andExpect(status().isForbidden());verifyNoInteractions(service);}
}
