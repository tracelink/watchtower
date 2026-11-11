package com.tracelink.appsec.watchtower.core.assistant;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;

@SpringBootTest(classes=WatchtowerTestApplication.class,properties={"watchtower.assistant.recovery-delay-ms=600000"})
@AutoConfigureMockMvc
class AssistantWebTest {
 @Autowired MockMvc mvc;
 @MockitoBean AssistantSettingsService settings;
 @MockitoBean AssistantAccess access;
 @MockitoBean AssistantPersistence db;
 @MockitoBean AssistantMaintenance maintenance;
 @MockitoBean AssistantToolRegistry tools;
 @MockitoBean com.tracelink.appsec.watchtower.core.feedback.MissedVulnerabilityService missed;
 @MockitoBean com.tracelink.appsec.watchtower.core.rule.candidate.RuleCandidateService candidates;
 com.tracelink.appsec.watchtower.core.persistence.LedgerRepository records;
 @BeforeEach void setup(){records=mock(com.tracelink.appsec.watchtower.core.persistence.LedgerRepository.class);when(db.records()).thenReturn(records);}
 @Test void approvedKnowledgeNeedsRuleModifyAndCsrfToChangeAndExplainsInvalidProposals()throws Exception {
  mvc.perform(get("/rule/knowledge").with(user("viewer").authorities(()->"Assistant Use"))).andExpect(status().isForbidden());
  mvc.perform(get("/rule/knowledge?status=PROPOSED").with(user("viewer").authorities(()->"Ruleset View"))).andExpect(status().isOk());
  String body="{\"kind\":\"SANITIZER\",\"statement\":\"Encode.forHtml escapes HTML output\",\"language\":\"java\",\"library\":\"OWASP Java Encoder\",\"versionRange\":\"1.2.x\",\"allRepositories\":true,\"evidence\":[]}";
  mvc.perform(post("/rule/knowledge").with(csrf()).with(user("viewer").authorities(()->"Ruleset View")).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
  var steward=user("steward").authorities(()->"Rule Modify");
  mvc.perform(post("/rule/knowledge").with(steward).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
  mvc.perform(post("/rule/knowledge").with(steward).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isBadRequest())
   .andExpect(jsonPath("$.error").value("Give 1 to 20 evidence references"));
  mvc.perform(post("/rule/knowledge/unknown/approve").with(steward).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{\"version\":0}")).andExpect(status().isNotFound());
 }
 @Test void findingAssessmentNeedsAssistantUseAndCsrfAndAgreementNeedsAdminOrAudit()throws Exception {
  String body="{\"scanType\":\"pull_request\",\"scanId\":5,\"findingKey\":\"9\"}";
  mvc.perform(post("/finding-assessment").with(csrf()).with(user("viewer").authorities(()->"Scan Results View")).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
  mvc.perform(post("/finding-assessment").with(user("engineer").authorities(()->"Assistant Use")).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
  mvc.perform(post("/finding-assessment").with(csrf()).with(user("engineer").authorities(()->"Assistant Use")).contentType(MediaType.APPLICATION_JSON).content("{\"scanType\":\"pull_request\"}")).andExpect(status().isBadRequest());
  mvc.perform(get("/admin/assistant/assessment-agreement").with(user("engineer").authorities(()->"Assistant Use"))).andExpect(status().isForbidden());
  mvc.perform(get("/admin/assistant/assessment-agreement").with(user("auditor").authorities(()->"Assistant Audit"))).andExpect(status().isOk()).andExpect(jsonPath("$.blind_cases").value(0));
 }
 @Test void moduleControlsRequireIndependentAuthorityCsrfAndBlockDisabledDesignerRoutes()throws Exception {
  var reviewer=user("engineer").authorities(()->"Module Settings Modify");
  if(moduleRegistry.getScannerNames().stream().noneMatch(n->n.equalsIgnoreCase("Regex")))moduleRegistry.registerScanner("Regex",mock(com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner.class));
  mvc.perform(get("/configuration/modules").with(user("viewer").authorities(()->"Rule Modify"))).andExpect(status().isForbidden());
  mvc.perform(get("/configuration/modules").with(reviewer)).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("Scanner modules"))).andExpect(content().string(org.hamcrest.Matchers.containsString("data-module=\"regex\"")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("role=\"switch\"")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Turning one off")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("class=\"badge\""))));
  mvc.perform(post("/configuration/modules").with(reviewer).param("module","regex").param("enabled","false").param("version","0")).andExpect(status().isForbidden());
  var controls=org.springframework.test.util.ReflectionTestUtils.getField(moduleWebConfiguration,"controls");
  var policies=(com.tracelink.appsec.watchtower.core.module.ModuleControlService)controls;
  mvc.perform(post("/configuration/modules").with(reviewer).with(csrf()).param("module","regex").param("enabled","false").param("version",Long.toString(policies.policy("regex").version()))).andExpect(status().is3xxRedirection());
  try{mvc.perform(post("/designer/regex/query").with(reviewer).with(csrf()).param("query","x").param("source","private")).andExpect(status().isConflict());}
  finally{policies.change("regex",true,policies.policy("regex").version(),"reviewer");}
 }
 @Test void assistantPagesUsePlainWordsAndLeadBackToSettings()throws Exception {
  var admin=user("assistant-admin").authorities(()->"Assistant Admin",()->"Assistant Audit");
  mvc.perform(get("/admin/assistant").with(admin)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-assistant-ready-chip")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Limits for one answer")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("suffix-text=\"USD / day\"")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Save advanced settings"))))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("assistant-limits-dialog"))))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-ai-integration-replace")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("watchtower.encryption"))));
  mvc.perform(get("/admin/assistant").with(user("auditor").authorities(()->"Assistant Audit"))).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("data-ai-integration-dialog"))))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("data-assistant-settings-save"))));
  var evaluationPage=mvc.perform(get("/admin/assistant/evaluation").with(admin)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("<a href=\"/admin/assistant\">AI assistant settings</a>")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Back to assistant settings"))))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("evaluation-answer-dialog"))).andReturn();
  java.nio.file.Files.writeString(java.nio.file.Path.of("/private/tmp/watchtower-evaluation-render.html"),evaluationPage.getResponse().getContentAsString());
 }
 @Autowired com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService moduleRegistry;
 @Autowired com.tracelink.appsec.watchtower.core.module.ModuleWebConfiguration moduleWebConfiguration;
 @Test void candidateWorkflowRequiresExplicitRuleAuthorityCsrfAndSourceGrantForShadow()throws Exception {
  var reviewer=user("reviewer").authorities(()->"Rule Modify");
  mvc.perform(get("/rule/candidates/workspace/42").with(user("viewer").authorities(()->"Assistant Use"))).andExpect(status().isForbidden());
  when(candidates.workspace(42)).thenReturn(new com.tracelink.appsec.watchtower.core.rule.candidate.RuleCandidateWorkspace(42,"revision",Map.of(),Set.of(),Map.of(),false,List.of("Unsupported"),false,List.of(),List.of(),List.of()));
  mvc.perform(get("/rule/candidates/workspace/42").with(reviewer)).andExpect(status().isOk()).andExpect(jsonPath("$.ruleId").value(42));
  String id=UUID.randomUUID().toString(),body="{\"version\":1,\"revision\":\""+"a".repeat(64)+"\",\"rationale\":\"Reviewed exact evidence\"}";
  mvc.perform(post("/rule/candidates/"+id+"/promote").with(reviewer).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
  mvc.perform(post("/rule/candidates/"+id+"/promote").with(reviewer).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isOk());
  verify(candidates).transition(eq(id),eq("PROMOTE"),any(),eq("reviewer"));
  doThrow(new org.springframework.security.access.AccessDeniedException("revoked")).when(access).require("reviewer","Assistant Source Read");
  mvc.perform(post("/rule/candidates/"+id+"/shadow").with(reviewer).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
  verify(candidates,never()).transition(eq(id),eq("SHADOW"),any(),anyString());
 }
 @Test void candidateHttpValuesPreserveScalarsContainersEmptyAndNull()throws Exception {
  var requestType=com.tracelink.appsec.watchtower.core.rule.candidate.RuleCandidateWorkspace.DraftRequest.class;
  when(candidates.create(any(requestType),eq("reviewer"))).thenReturn("draft");
  mvc.perform(post("/rule/candidates").with(user("reviewer").authorities(()->"Rule Modify")).with(csrf()).contentType(MediaType.APPLICATION_JSON)
   .content("{\"ruleId\":42,\"baseRevision\":\"revision\",\"changes\":{\"text\":\"\",\"number\":1.25,\"array\":[1,\"x\"],\"object\":{\"key\":false},\"emptyArray\":[],\"emptyObject\":{},\"nullable\":null}}"))
   .andExpect(status().isOk()).andExpect(jsonPath("$.id").value("draft"));
  var capture=org.mockito.ArgumentCaptor.forClass(requestType);verify(candidates).create(capture.capture(),eq("reviewer"));
  var values=capture.getValue().changes();
  org.junit.jupiter.api.Assertions.assertEquals("",values.get("text"));
  org.junit.jupiter.api.Assertions.assertEquals(1.25,((Number)values.get("number")).doubleValue());
  org.junit.jupiter.api.Assertions.assertInstanceOf(List.class,values.get("array"));
  org.junit.jupiter.api.Assertions.assertEquals(Map.of("key",false),values.get("object"));
  org.junit.jupiter.api.Assertions.assertEquals(List.of(),values.get("emptyArray"));
  org.junit.jupiter.api.Assertions.assertEquals(Map.of(),values.get("emptyObject"));
  org.junit.jupiter.api.Assertions.assertTrue(values.containsKey("nullable"));
  org.junit.jupiter.api.Assertions.assertNull(values.get("nullable"));
 }
 @Test void featureGuideRemainsAvailableWithChatDisabledWithoutGrantingFeatureAccess()throws Exception{
  mvc.perform(get("/help/features").with(user("viewer")))
   .andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Rule owner and status")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("the drawer says what is missing")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("href=\"/admin/assistant\""))))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("href=\"/rule/edit\""))));
  mvc.perform(get("/help/features")).andExpect(status().is3xxRedirection());
 }
 @Test void featureGuideUsesCurrentVisibilityAndShowsAuthorizedEntryPoints()throws Exception{
  when(settings.available()).thenReturn(true);
  mvc.perform(get("/help/features").with(user("reviewer").authorities(()->"Rule Modify",()->"Scan Results View",()->"Assistant Admin",()->"Assistant Use")))
   .andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Assistant and Explain appear for every role with Assistant Use")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("href=\"/rule/edit\"")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("href=\"/admin/assistant\"")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("/help/features#assistant")));
 }
 @Test void reviewReportViewRunAndScheduleRequireSeparateAuthorityAndCsrf()throws Exception{
  mvc.perform(get("/rule/review-report").with(user("viewer").authorities(()->"Assistant Use"))).andExpect(status().isForbidden());
  mvc.perform(get("/rule/review-report").with(user("viewer").authorities(()->"Ruleset View"))).andExpect(status().isOk()).andExpect(jsonPath("$.settings.weekday").value(1));
  mvc.perform(post("/rule/review-report/run").with(csrf()).with(user("viewer").authorities(()->"Ruleset View"))).andExpect(status().isForbidden());
  var steward=user("steward").authorities(()->"Rule Modify",()->"Ruleset View");
  mvc.perform(post("/rule/review-report/run").with(steward)).andExpect(status().isForbidden());
  mvc.perform(post("/rule/review-report/settings").with(steward).contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false,\"weekday\":2,\"version\":0}")).andExpect(status().isForbidden());
  mvc.perform(post("/rule/review-report/settings").with(steward).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":true,\"weekday\":9,\"version\":0}")).andExpect(status().isBadRequest());
  mvc.perform(post("/rule/review-report/run").with(steward).with(csrf())).andExpect(status().isOk()).andExpect(jsonPath("$.report.trigger").value("MANUAL")).andExpect(jsonPath("$.report.actor").value("steward"))
   .andExpect(jsonPath("$.report.summary.matrix.rows[0].cwe").value("CWE-79"));
  mvc.perform(post("/rule/review-report/run").with(steward).with(csrf())).andExpect(status().isTooManyRequests());
  // R5.4: anyone who can view rulesets sees upstream updates; only Rule Modify with CSRF releases held rules.
  mvc.perform(get("/rule/upstream-updates").with(user("viewer").authorities(()->"Assistant Use"))).andExpect(status().isForbidden());
  mvc.perform(get("/rule/upstream-updates").with(user("viewer").authorities(()->"Ruleset View"))).andExpect(status().isOk());
  String approve="/rule/upstream-updates/"+UUID.randomUUID()+"/approve";
  mvc.perform(post(approve).with(user("viewer").authorities(()->"Ruleset View")).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{\"version\":0}")).andExpect(status().isForbidden());
  mvc.perform(post(approve).with(steward).contentType(MediaType.APPLICATION_JSON).content("{\"version\":0}")).andExpect(status().isForbidden());
  mvc.perform(post(approve).with(steward).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{\"version\":0}")).andExpect(status().isNotFound());
  mvc.perform(post(approve).with(steward).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isBadRequest());
 }
 @Test void findSimilarCodeRequiresSourceGrantsAndRuleModifyWithCsrfToStart()throws Exception{
  String caseId=UUID.randomUUID().toString();
  var viewer=user("viewer").authorities(()->"Assistant Source Read",()->"Repository Settings View",()->"Scan Results View");
  var steward=user("steward").authorities(()->"Rule Modify",()->"Assistant Source Read",()->"Repository Settings View",()->"Scan Results View");
  mvc.perform(get("/repository/evidence/variants/repositories").with(user("ruler").authorities(()->"Rule Modify"))).andExpect(status().isForbidden());
  mvc.perform(get("/repository/evidence/missed/case/"+caseId+"/proposal").with(user("ruler").authorities(()->"Rule Modify"))).andExpect(status().isForbidden());
  String body="{\"caseId\":\""+caseId+"\",\"repositoryIds\":[1]}";
  mvc.perform(post("/repository/evidence/variants").with(viewer).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
  mvc.perform(post("/repository/evidence/variants").with(steward).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
  mvc.perform(post("/repository/evidence/missed/case/"+caseId+"/fixtures").with(viewer).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{\"ruleId\":1}")).andExpect(status().isForbidden());
  mvc.perform(post("/repository/evidence/missed/case/"+caseId+"/fixtures").with(steward).contentType(MediaType.APPLICATION_JSON).content("{\"ruleId\":1}")).andExpect(status().isForbidden());
  mvc.perform(post("/repository/evidence/missed/case/"+caseId+"/fixtures").with(steward).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isBadRequest());
  mvc.perform(get("/repository/evidence/variants/not-a-uuid").with(viewer)).andExpect(status().isBadRequest());
 }
 @Test void chatNotReadyRefusesChatButStatusAndDrawerExplainWhy()throws Exception{
  var engineer=user("engineer").authorities(()->"Assistant Use");
  var missing=new AssistantSettingsService.Readiness(false,"NO_API_KEY","No OpenAI API key is configured. An Assistant Admin can add it in Assistant settings → AI integration.");
  when(settings.readiness()).thenReturn(missing);
  mvc.perform(get("/assistant/history").with(engineer)).andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.error").value(missing.message()));verify(db,never()).history(anyString(),anyInt());
  mvc.perform(get("/assistant/turn/"+UUID.randomUUID()+"/events").with(engineer)).andExpect(status().isServiceUnavailable());verify(db,never()).turn(anyString());
  mvc.perform(get("/assistant/status").with(engineer)).andExpect(status().isOk()).andExpect(jsonPath("$.ready").value(false)).andExpect(jsonPath("$.problem").value("NO_API_KEY"));
  mvc.perform(get("/assistant/status").with(user("viewer"))).andExpect(status().isForbidden());
  // No deployment switch: the drawer and the sidebar entry render for Assistant Use even while chat cannot answer.
  mvc.perform(get("/help/features").with(engineer)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("<wt-assistant-drawer"))).andExpect(content().string(org.hamcrest.Matchers.containsString("data-assistant-setup")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-assistant-open")));
  mvc.perform(get("/help/features").with(user("viewer"))).andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("<wt-assistant-drawer"))));
 }
 @Test void ordinaryRoleCannotUseChatOrAdminSettings()throws Exception{
  when(settings.available()).thenReturn(true);
  mvc.perform(get("/assistant/history").with(user("engineer"))).andExpect(status().isForbidden());
  mvc.perform(get("/assistant/turn/"+UUID.randomUUID()+"/events").with(user("engineer"))).andExpect(status().isForbidden());
  mvc.perform(get("/admin/assistant/settings").with(user("engineer").authorities(()->"Assistant Use"))).andExpect(status().isForbidden());
  mvc.perform(get("/repository/evidence/missed/42").with(user("engineer").authorities(()->"Rule Modify",()->"Scan Results View",()->"Repository Settings View"))).andExpect(status().isForbidden());
  var reviewer=user("reviewer").authorities(()->"Rule Modify",()->"Assistant Source Read",()->"Scan Results View",()->"Repository Settings View");
  mvc.perform(post("/repository/evidence/missed").with(reviewer).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
  when(missed.save(any(),eq("reviewer"))).thenReturn("confirmed-case");
  String caseBody=AssistantState.mapper().writeValueAsString(new com.tracelink.appsec.watchtower.core.feedback.MissedVulnerabilityService.Intake(42,"a".repeat(40),null,"app/source.py",1,"PENTEST","pentest/report-42","CWE-79",null,null,"fixtures/xss-v1.py","b".repeat(64),"python","unknown","unknown"));
  mvc.perform(post("/repository/evidence/missed").with(reviewer).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(caseBody)).andExpect(status().isOk()).andExpect(jsonPath("$.id").value("confirmed-case"));
 }
 @Test void turnSubmissionAndProgressStreamRequireCurrentAccess()throws Exception{
  when(settings.available()).thenReturn(true);
  String id=UUID.randomUUID().toString();var turn=new AssistantPersistence.Turn(id,"session","engineer","COMPLETED","fixture-model","low","{}","key",null,1,1,Long.MAX_VALUE,0,0,null);
  var state=new AssistantState();state.finish("Streamed answer");when(db.turn(id)).thenReturn(turn);when(db.state(turn)).thenReturn(state);when(db.session("session","engineer")).thenReturn(Map.of("expires_at",1L));
  state.activity.addObject().put("tool","get_rule").put("status","read");
  mvc.perform(get("/assistant/turn/"+id).with(user("engineer").authorities(()->"Assistant Use"))).andExpect(status().isOk()).andExpect(jsonPath("$.activity").isArray()).andExpect(jsonPath("$.activity[0].tool").value("get_rule"));
  var stream=mvc.perform(get("/assistant/turn/"+id+"/events").with(user("engineer").authorities(()->"Assistant Use"))).andExpect(request().asyncStarted()).andExpect(header().string("X-Accel-Buffering","no")).andReturn();
  mvc.perform(asyncDispatch(stream)).andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_EVENT_STREAM)).andExpect(content().string(org.hamcrest.Matchers.containsString("\"answer\":\"Streamed answer\""))).andExpect(content().string(org.hamcrest.Matchers.containsString("\"activity\":[{\"tool\":\"get_rule\",\"status\":\"read\"}]")));
  var request="{\"message\":\"Explain\",\"idempotencyKey\":\""+UUID.randomUUID()+"\"}";
  mvc.perform(post("/assistant/turn").with(user("engineer").authorities(()->"Assistant Use")).contentType(MediaType.APPLICATION_JSON).content(request)).andExpect(status().isForbidden());verify(db,never()).submit(any(),anyString());
  doThrow(new org.springframework.security.access.AccessDeniedException("revoked")).when(access).require("engineer","Assistant Use");
  mvc.perform(post("/assistant/turn").with(csrf()).with(user("engineer").authorities(()->"Assistant Use")).contentType(MediaType.APPLICATION_JSON).content(request)).andExpect(status().isForbidden());verify(db,never()).submit(any(),anyString());
  mvc.perform(get("/assistant/turn/"+id+"/events").with(user("engineer").authorities(()->"Assistant Use"))).andExpect(status().isForbidden());
 }
 @Test void answerEvaluationIsAdminOnlyAndStartingOrScoringNeedsCsrf()throws Exception{
  mvc.perform(get("/admin/assistant/evaluations").with(user("auditor").authorities(()->"Assistant Audit"))).andExpect(status().isForbidden());
  var admin=user("assistant-admin").authorities(()->"Assistant Admin",()->"Assistant Use");
  mvc.perform(post("/admin/assistant/evaluations").with(admin).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
  mvc.perform(post("/admin/assistant/evaluations/results/"+UUID.randomUUID()+"/score").with(admin).contentType(MediaType.APPLICATION_JSON).content("{\"score\":4,\"version\":0}")).andExpect(status().isForbidden());
  mvc.perform(post("/admin/assistant/evaluations/results/"+UUID.randomUUID()+"/score").with(admin).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{\"version\":0}")).andExpect(status().isBadRequest());
  // Chat is off in this context (mocked settings): a run is refused rather than silently doing nothing.
  when(settings.readiness()).thenReturn(new AssistantSettingsService.Readiness(false,"CHAT_OFF","Chat is turned off. An Assistant Admin can turn it on in Assistant settings."));
  mvc.perform(post("/admin/assistant/evaluations").with(admin).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isConflict());
  mvc.perform(get("/admin/assistant/evaluations").with(admin)).andExpect(status().isOk());
 }
 @Test void aiIntegrationKeyIsAdminOnlyWriteOnlyAndChangesNeedCsrf()throws Exception{
  String path="/admin/assistant/integrations/openai";
  mvc.perform(get(path).with(user("auditor").authorities(()->"Assistant Audit"))).andExpect(status().isForbidden());
  mvc.perform(get(path).with(user("user").authorities(()->"Assistant Use"))).andExpect(status().isForbidden());
  var admin=user("assistant-admin").authorities(()->"Assistant Admin");
  String key="{\"apiKey\":\"sk-proj-synthetic0000000000000000000000\",\"version\":0}";
  mvc.perform(post(path).with(admin).contentType(MediaType.APPLICATION_JSON).content(key)).andExpect(status().isForbidden());
  mvc.perform(post(path+"/remove").with(admin).contentType(MediaType.APPLICATION_JSON).content("{\"version\":0}")).andExpect(status().isForbidden());
  mvc.perform(post(path+"/test").with(admin).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
  mvc.perform(post(path).with(admin).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{\"apiKey\":\"not-a-key\",\"version\":0}")).andExpect(status().isBadRequest())
    .andExpect(jsonPath("$.error").value("Enter an OpenAI API key; it starts with sk-."));
  mvc.perform(get("/admin/assistant/integrations/unknown").with(admin)).andExpect(status().isBadRequest());
  mvc.perform(get(path).with(admin)).andExpect(status().isOk()).andExpect(jsonPath("$.name").value("OpenAI")).andExpect(jsonPath("$.apiKey").doesNotExist());
  // With no stored key the test reports it without calling the provider.
  mvc.perform(post(path+"/test").with(admin).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isOk())
    .andExpect(jsonPath("$.ok").value(false)).andExpect(jsonPath("$.integration.healthError").value("PROVIDER_AUTHENTICATION"));
 }
 @Test void auditGrantDoesNotGrantSettingsOrToolExecutionAndPageRenders()throws Exception{
  mvc.perform(get("/admin/assistant").with(user("auditor").authorities(()->"Assistant Audit"))).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("data-assistant-audit")));
  mvc.perform(get("/admin/assistant/settings").with(user("auditor").authorities(()->"Assistant Audit"))).andExpect(status().isForbidden());
  when(settings.available()).thenReturn(true);mvc.perform(get("/assistant/models").with(user("auditor").authorities(()->"Assistant Audit"))).andExpect(status().isForbidden());
 }
 @Test void activeTurnLookupUsesSharedOwnerIdentity()throws Exception{
  when(settings.available()).thenReturn(true);
  when(records.maps(eq("SELECT turnId AS turn_id,sessionId AS session_id FROM AssistantTurnEntity WHERE activeUser=?1"),eq(0),eq(1),eq(AssistantPersistence.ownerKey("engineer")))).thenReturn(List.of(Map.of("turn_id",UUID.randomUUID().toString(),"session_id","session")));
  mvc.perform(get("/assistant/active").with(user("engineer").authorities(()->"Assistant Use"))).andExpect(status().isOk()).andExpect(jsonPath("$[0].session_id").value("session"));
 }
 @Test void enabledDrawerRendersOutsideBoostedContentForAuthorizedUsers()throws Exception{
  when(settings.available()).thenReturn(true);
  mvc.perform(get("/admin/assistant").with(user("assistant-admin").authorities(()->"Assistant Admin",()->"Assistant Use"))).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("id=\"wt-assistant-drawer\""))).andExpect(content().string(org.hamcrest.Matchers.containsString("hx-target=\"#wt-assistant-drawer\"")));
 }
 @Test void auditSummaryKeepsSourceFreeUsageAfterTranscriptExpiry()throws Exception{
  when(records.maps(contains("FROM AssistantSessionEntity s"),eq(0),eq(20))).thenReturn(List.of(Map.of("session_id","session","transcript_purged_at",2L,"tokens",0L,"cost_micros",0L)));
  mvc.perform(get("/admin/assistant/audit").with(user("auditor").authorities(()->"Assistant Audit"))).andExpect(status().isOk()).andExpect(jsonPath("$.sessions[0].transcript_purged_at").value(2)).andExpect(jsonPath("$.sessions[0].tokens").value(0)).andExpect(jsonPath("$.sessions[0].cost_micros").value(0));
 }

 @Test void auditTranscriptUsesAJsonArrayAndThePageUsesTheSameMessages()throws Exception{
  String session=UUID.randomUUID().toString(),key="transcript";
  long expires=System.currentTimeMillis()+60_000;
  when(records.maps(contains("FROM AssistantSessionEntity"),eq(0),eq(Integer.MAX_VALUE),eq(session)))
   .thenReturn(List.of(Map.of("expires_at",expires,"latest_key",key)));
  var store=mock(AssistantTranscriptStore.class);when(db.store()).thenReturn(store);
  var state=new AssistantState();state.user("Explain rule 11");state.finish("Rule 11 <b>detects</b> passwords.");
  when(store.get(key,1048576)).thenReturn(state.encode(1048576));
  var auditor=user("auditor").authorities(()->"Assistant Audit");
  mvc.perform(get("/admin/assistant/transcript/"+session).with(auditor)).andExpect(status().isOk())
   .andExpect(jsonPath("$.messages").isArray()).andExpect(jsonPath("$.messages.length()").value(2))
   .andExpect(jsonPath("$.messages[0].role").value("user"))
   .andExpect(jsonPath("$.messages[1].text").value("Rule 11 <b>detects</b> passwords."))
   .andExpect(jsonPath("$.expiresAt").value(expires));
  mvc.perform(get("/admin/assistant/transcripts/"+session).with(auditor)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Rule 11 &lt;b&gt;detects&lt;/b&gt; passwords.")));
  verify(tools,times(2)).auditReplay(eq("auditor"),any(AssistantState.class));
  verify(db,times(2)).audit("auditor",session,null,"AUDIT_TRANSCRIPT_VIEW",null,null,null,0,0);
  mvc.perform(get("/admin/assistant/transcript/"+session).with(user("assistant-admin").authorities(()->"Assistant Admin"))).andExpect(status().isForbidden());
  // An auditor missing a grant the chat's tools needed gets an explanation on the page, not a bare 403
  org.mockito.Mockito.doThrow(new org.springframework.security.access.AccessDeniedException("grant")).when(tools).auditReplay(eq("auditor"),any(AssistantState.class));
  mvc.perform(get("/admin/assistant/transcripts/"+session).with(auditor)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-transcript-denied")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Rule 11"))));
 }

 /** UAT #19: evaluation and transcripts are pages; their permissions match the endpoints they replace. */
 @Test void evaluationAndTranscriptArePagesWithTheSamePermissions()throws Exception{
  var admin=user("assistant-admin").authorities(()->"Assistant Admin");
  var auditor=user("auditor").authorities(()->"Assistant Audit");
  mvc.perform(get("/admin/assistant/evaluation").with(admin)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-evaluation-page")));
  mvc.perform(get("/admin/assistant/evaluation").with(auditor)).andExpect(status().isForbidden());
  String session=UUID.randomUUID().toString();
  mvc.perform(get("/admin/assistant/transcripts/"+session).with(auditor)).andExpect(status().isNotFound());
  when(records.maps(org.mockito.ArgumentMatchers.anyString(),org.mockito.ArgumentMatchers.anyInt(),org.mockito.ArgumentMatchers.anyInt(),org.mockito.ArgumentMatchers.any()))
   .thenReturn(java.util.List.of(new java.util.HashMap<>(java.util.Map.of("expires_at",1L))));
  mvc.perform(get("/admin/assistant/transcripts/"+session).with(auditor)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("This transcript has expired")));
  mvc.perform(get("/admin/assistant/transcripts/"+session).with(admin)).andExpect(status().isForbidden());
 }
}
