package com.tracelink.appsec.watchtower.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.watchtower.core.assistant.*;
import com.tracelink.appsec.watchtower.core.assistant.integration.*;
import com.tracelink.appsec.watchtower.core.assistant.actions.*;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.ruleset.*;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;

/** Actual secured routes and full desktop templates; no provider requests or real scans. */
@SpringBootTest(properties={"watchtower.runAfterStartup=false","watchtower.rule-testing.enabled=false","spring.datasource.url=jdbc:h2:mem:ai-reviewed-workflows;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@AutoConfigureMockMvc @ActiveProfiles("dev") @Transactional
class AiReviewedWorkflowsMvcTest {
 @MockitoBean com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
 @MockitoBean AssistantAccess access;
 @MockitoBean AiIntegrationService integrations;
 @Autowired MockMvc mvc;@Autowired RuleRepository rules;@Autowired LedgerRepository records;@Autowired AssistantSettingsService settings;@Autowired RulesetService rulesets;
 long ruleId;
 final org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor admin=user("engineer").authorities(()->"Assistant Use",()->"Ruleset View",()->"Ruleset Modify",()->"Rule Modify",()->"Scan Results View",()->"Assistant Admin",()->"Repository Settings View",()->"Repository Settings Modify");
 @BeforeEach void seed(){
  when(access.authorities(anyString())).thenReturn(Set.of("Assistant Use","Ruleset View","Ruleset Modify","Rule Modify","Scan Results View","Assistant Admin","Repository Settings View","Repository Settings Modify"));
  when(integrations.view(AiProvider.OPENAI)).thenReturn(new AiIntegrationService.View("OPENAI","OpenAI",true,null,null,null,null,null,1,true));
  var dto=new RegexCustomRuleDto();dto.setName("AI review <script> fixture");dto.setAuthor("engineer");dto.setMessage("Example match");dto.setExternalUrl("https://example.test/rule");dto.setPriority(RulePriority.HIGH);dto.setRegexPattern("unsafe|risky");dto.setFileExtension("");ruleId=rules.saveAndFlush(dto.toEntity()).getId();
 }
 @Test void improvementAndModelSetupPagesRenderAndRequireTheirGrants()throws Exception {
  mvc.perform(get("/rules/"+ruleId+"/improvements").with(admin)).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("Save draft"))).andExpect(content().string(org.hamcrest.Matchers.containsString("No reviewed findings yet"))).andExpect(content().string(org.hamcrest.Matchers.containsString("Improve AI review &lt;script&gt; fixture"))).andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("MVP"))));
  mvc.perform(get("/rule/evidence/"+ruleId+"/health").with(admin)).andExpect(status().isOk()).andExpect(jsonPath("$.header_chips[0].text").value("Too little data"));
  mvc.perform(get("/rules/"+ruleId+"/improvements/evidence").with(admin)).andExpect(status().isOk()).andExpect(jsonPath("$.ruleId").value(ruleId)).andExpect(jsonPath("$.baseRevision").isString()).andExpect(jsonPath("$.references[0].data.definition.name").value("AI review <script> fixture"));
  mvc.perform(get("/rules/"+ruleId+"/improvements").with(user("reader").authorities(()->"Ruleset View"))).andExpect(status().isForbidden());
  var rendered=mvc.perform(get("/admin/assistant").with(admin)).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("Validate and approve model"))).andExpect(content().string(org.hamcrest.Matchers.containsString("data-assistant-ruleset-actions"))).andReturn();
  java.nio.file.Files.writeString(java.nio.file.Path.of("/private/tmp/watchtower-assistant-admin-render.html"),rendered.getResponse().getContentAsString());
 }
 void enableActions(){var node=(com.fasterxml.jackson.databind.node.ObjectNode)AssistantState.mapper().valueToTree(settings.get().settings());node.put("enabled",true).put("rulesetActionsEnabled",true).put("defaultModel","fixture-model").put("defaultEffort","low");node.putArray("allowedModels").addObject().put("id","fixture-model").put("inputTokenLimit",24000).put("outputTokenLimit",8192).put("inputMicrosPerMillion",750000).put("outputMicrosPerMillion",4500000).put("validatedAt","2026-10-19").put("validationRef","fixture:responses-v1").putArray("efforts").add("low");settings.save(new AssistantSettingsService.Versioned(settings.get().version(),settings.decode(node.toString())),"admin");}
 @Test void exactReviewRendersCsrfIsRequiredAndReceiptsAreIdempotent()throws Exception {
  enableActions();var set=rulesets.createRuleset("Disposable review set","Original description",RulesetDesignation.PRIMARY);long id=set.getId();
  String request="{\"idempotencyKey\":\""+UUID.randomUUID()+"\",\"operations\":[{\"type\":\"UPDATE\",\"target\":\""+id+"\",\"name\":\"Edited set\",\"description\":\"Reviewed\",\"designation\":\"PRIMARY\"}]}";
  mvc.perform(post("/assistant/change-sets").with(admin).contentType("application/json").content(request)).andExpect(status().isForbidden());
  var prepared=mvc.perform(post("/assistant/change-sets").with(admin).with(csrf()).contentType("application/json").content(request)).andExpect(status().isOk()).andReturn();var draft=AssistantState.mapper().readTree(prepared.getResponse().getContentAsString());String changeId=draft.path("id").asText();
  mvc.perform(get("/assistant/change-sets/"+changeId+"/review").with(admin)).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("Approve and apply")));
  assertEquals("Disposable review set",rulesets.getRuleset(id).getName());String approve="{\"version\":"+draft.path("version").asLong()+",\"contentHash\":\""+draft.path("contentHash").asText()+"\",\"deletionNames\":{}}";
  mvc.perform(post("/assistant/change-sets/"+changeId+"/apply").with(admin).with(csrf()).contentType("application/json").content(approve)).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("APPLIED")).andExpect(jsonPath("$.receipt").exists());
  mvc.perform(post("/assistant/change-sets/"+changeId+"/apply").with(admin).with(csrf()).contentType("application/json").content(approve)).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("APPLIED"));assertEquals("Edited set",rulesets.getRuleset(id).getName());
 }
 @Test void disabledFeaturesFailWithoutApplicationMutations()throws Exception {
  mvc.perform(post("/assistant/change-sets").with(admin).with(csrf()).contentType("application/json").content("{\"idempotencyKey\":\""+UUID.randomUUID()+"\",\"operations\":[{\"type\":\"DEFAULT\",\"target\":null}]}" )).andExpect(status().isServiceUnavailable());
  mvc.perform(post("/rules/"+ruleId+"/improvements").with(admin).with(csrf()).contentType("application/json").content("{\"idempotencyKey\":\""+UUID.randomUUID()+"\",\"days\":90,\"evidenceIds\":[],\"question\":\"Investigate\",\"language\":\"\"}" )).andExpect(status().isServiceUnavailable());
  assertEquals(0,records.scalar(Long.class,"SELECT COUNT(c) FROM RulesetChangeSetEntity c"));
 }
}
