package com.tracelink.appsec.watchtower.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.module.awssecurity.*;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Ordinary MVC/JPA behavior; no real provider, queues or migration acceptance checks. */
@SpringBootTest(properties={"watchtower.runAfterStartup=false","watchtower.rule-testing.enabled=false",
 "spring.datasource.url=jdbc:h2:mem:aws-setup-ui;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
 "watchtower.aws-security.region=us-east-1",
 "watchtower.aws-security.account=123456789012","watchtower.aws-security.space-id=space","watchtower.aws-security.service-role=arn:aws:iam::123456789012:role/testing",
 "watchtower.aws-security.input-bucket=synthetic-fixture","watchtower.aws-security.queue-url=https://sqs.us-east-1.amazonaws.com/123456789012/testing.fifo"})
@AutoConfigureMockMvc @ActiveProfiles("dev") @Transactional
@org.springframework.context.annotation.Import(AwsSecuritySetupMvcTest.ReportFixture.class)
class AwsSecuritySetupMvcTest {
 @MockitoBean com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
 @MockitoBean AwsSecurityQueue queue;@MockitoBean AwsSecuritySetupAccess access;@MockitoBean AwsSecurityReadiness readiness;@MockitoBean AwsSecurityImporter importer;
 @Autowired com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository repositories;
 @Autowired MockMvc mvc;@Autowired AwsSecuritySettings settings;@Autowired AwsSecurityRunRepository runs;@Autowired AwsSecurityPermitRepository permits;
 final org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor admin=user("engineer").authorities(()->"AWS Security Administration",()->"Repository Settings View");
 @BeforeEach void ready(){when(readiness.check()).thenReturn(new AwsSecurityReadiness.Result(true,1,"Resource checks passed",java.util.List.of(
  new AwsSecurityReadiness.Check("Runtime account","VERIFIED","Account matches")),"arn:aws:sts::123456789012:assumed-role/runtime/pod"));when(importer.sharedArtifacts()).thenReturn(true);}
 @Test void realDesktopPageRendersChecksAndSeparateSetupDialogs()throws Exception{
  var result=mvc.perform(get("/aws-security/readiness/view").with(user("engineer").authorities(()->"AWS Security Administration",()->"Repository Settings View",()->"Scan Results View"))).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("aws-delete-review-dialog")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Check repository access"))))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("aws-setup-result-dialog")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("aws-connection-dialog")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("How it works")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString(" connection checks ")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Show source for AWS findings")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("suffix-text=\"of 5\"")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-active-tab=\"status\"")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("SECURITY MISCONFIGURATION"))))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("AWS Security Agent setup"))))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("WATCHTOWER_AWS_SECURITY_CANARY_APPROVED"))))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("data-assistant-admin")))).andReturn();
  java.nio.file.Files.writeString(java.nio.file.Path.of("/private/tmp/watchtower-aws-setup-render.html"),result.getResponse().getContentAsString());
 }
 @Test void oneSaveChangesReviewLimitAndSourceSwitchWithCsrfAndSecretTypesStayBlocked()throws Exception{
  mvc.perform(post("/aws-security/settings").with(admin).param("limit","3")).andExpect(status().isForbidden());
  mvc.perform(post("/aws-security/settings").with(user("viewer").authorities(()->"Scan Results View")).with(csrf()).param("limit","3")).andExpect(status().isForbidden());
  var before=permits.findById(1).orElseThrow().sourceRiskTypes;
  mvc.perform(post("/aws-security/settings").with(admin).with(csrf()).param("limit","3").param("showSource","true"))
   .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/aws-security/readiness/view?tab=settings"));
  assertEquals(3, permits.findById(1).orElseThrow().configuredLimit);
  assertEquals(before, permits.findById(1).orElseThrow().sourceRiskTypes, "an unchanged switch writes nothing");
  mvc.perform(post("/aws-security/settings").with(admin).with(csrf()).param("limit","3").param("showSource","false")).andExpect(status().is3xxRedirection());
  assertEquals("", permits.findById(1).orElseThrow().sourceRiskTypes);
  mvc.perform(get("/aws-security/readiness/view").param("tab","settings").with(admin)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-active-tab=\"settings\"")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("aria-checked=\"false\"")));
  mvc.perform(post("/aws-security/settings").with(admin).with(csrf()).param("limit","3").param("showSource","true")).andExpect(status().is3xxRedirection());
  var types=permits.findById(1).orElseThrow().sourceRiskTypes;
  assertTrue(types.contains("SQL_INJECTION")&&types.contains("PRIVILEGE_ESCALATION"));
  assertFalse(types.toLowerCase().contains("secret")||types.toLowerCase().contains("credential"),"secret findings never show source");
  // Out of range comes back to the settings tab with a message; nothing is saved
  mvc.perform(post("/aws-security/settings").with(admin).with(csrf()).param("limit","6")).andExpect(status().is3xxRedirection())
   .andExpect(redirectedUrl("/aws-security/readiness/view?tab=settings")).andExpect(flash().attribute("failure",org.hamcrest.Matchers.containsString("1 to 5")));
  assertEquals(3, permits.findById(1).orElseThrow().configuredLimit);
 }
 @Test void theFailurePolicySwitchDefaultsToPassingAndIsSavedWithTheSameForm()throws Exception{
  mvc.perform(get("/aws-security/readiness/view").param("tab","settings").with(admin)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Let pull requests through when AWS can")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("name=\"bypassOnError\"")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-aws-bypass-switch")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Bypass on error")));
  assertNull(permits.findById(1).orElseThrow().failurePolicy,"nothing is saved until the switch is changed");
  mvc.perform(post("/aws-security/settings").with(admin).with(csrf()).param("limit","3").param("bypassOnError","false")).andExpect(status().is3xxRedirection());
  assertEquals("KEEP_INCOMPLETE",permits.findById(1).orElseThrow().failurePolicy);
  mvc.perform(get("/aws-security/readiness/view").param("tab","settings").with(admin)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Keep incomplete")));
  mvc.perform(post("/aws-security/settings").with(admin).with(csrf()).param("limit","3")).andExpect(status().is3xxRedirection());
  assertEquals("KEEP_INCOMPLETE",permits.findById(1).orElseThrow().failurePolicy,"a form that does not offer the choice leaves it alone");
  mvc.perform(post("/aws-security/settings").with(admin).with(csrf()).param("limit","3").param("bypassOnError","true")).andExpect(status().is3xxRedirection());
  assertEquals("PASS_ON_ERROR",permits.findById(1).orElseThrow().failurePolicy);
 }
 @Test void setupExplainsMissingSharedReportStorage()throws Exception{
  when(importer.sharedArtifacts()).thenReturn(false);
  mvc.perform(get("/aws-security/readiness/view").with(admin)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("configure shared S3 storage")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Manage access"))));
 }
 @Test void csrfAndDomainGrantsProtectAllSetupMutations()throws Exception{
  String body="{\"requestId\":\""+java.util.UUID.randomUUID()+"\",\"mode\":\"FULL\"}";
  mvc.perform(post("/aws-security/setup/tests").with(admin).contentType("application/json").content(body)).andExpect(status().isForbidden());
  mvc.perform(post("/aws-security/setup/tests").with(user("viewer").authorities(()->"Scan Results View")).with(csrf()).contentType("application/json").content(body)).andExpect(status().isForbidden());
 }
 @Test void explicitSyntheticRequestAndRetryKeepIdentity()throws Exception{
  String requestId=java.util.UUID.randomUUID().toString(),body="{\"requestId\":\""+requestId+"\",\"mode\":\"DIFFERENTIAL\"}";
  var first=mvc.perform(post("/aws-security/setup/tests").with(admin).with(csrf()).contentType("application/json").content(body)).andExpect(status().isOk()).andExpect(jsonPath("$.state").value("QUEUED")).andReturn();
  String id=new ObjectMapper().readTree(first.getResponse().getContentAsString()).path("id").asText();
  mvc.perform(post("/aws-security/setup/tests").with(admin).with(csrf()).contentType("application/json").content(body)).andExpect(status().isOk()).andExpect(jsonPath("$.id").value(id));
  assertNull(settings.configurationIssue());
  var run=runs.findById(id).orElseThrow();assertEquals("setup",run.parentType);assertEquals(0,run.repositoryId);assertTrue(run.dispatchPending);assertEquals("engineer",run.setupRequester);
  mvc.perform(get("/aws-security/setup/tests").with(admin)).andExpect(status().isOk()).andExpect(jsonPath("$[0].id").value(id));
  mvc.perform(post("/aws-security/setup/tests/"+id+"/stop").with(admin).with(csrf()).contentType("application/json").content("{}")).andExpect(status().isOk());
  assertTrue(runs.findById(id).orElseThrow().stopRequested);
 }
 @Test void separateAwsReportSectionHasUniqueIdsPortalLinksAndProtectedDeletion()throws Exception{
  var reviewer=user("reviewer").authorities(()->"Scan Results View",()->"AWS Security Administration",()->"Repository Settings View");
  var result=mvc.perform(get("/fixture/aws-report").with(reviewer)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("AWS review complete · 140 imported")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-finding-scanner-menu")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-scanner-group=\"aws\"")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-scanner-group=\"other\"")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString(">Command injection<")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("AWS security finding: COMMAND_INJECTION"))))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Other scanner findings"))))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-aws-titles-url=\"/reposcan/report/7/aws/titles?page=0\"")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Next AWS page")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Open this review in AWS")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Delete AWS review"))).andReturn();
  String html=result.getResponse().getContentAsString();var ids=java.util.regex.Pattern.compile("(?<![-a-zA-Z])id=\"([^\"]+)\"").matcher(html);var seen=new java.util.HashSet<String>();while(ids.find())assertTrue(seen.add(ids.group(1)),"Duplicate HTML id: "+ids.group(1));
  java.nio.file.Files.writeString(java.nio.file.Path.of("/private/tmp/watchtower-aws-report-render.html"),html);
  mvc.perform(get("/fixture/aws-report").with(user("viewer").authorities(()->"Scan Results View"))).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Delete AWS review"))));
  mvc.perform(post("/aws-security/runs/missing/delete-review").with(reviewer).param("reviewId","review").param("confirmation","DELETE")).andExpect(status().isForbidden());
  mvc.perform(post("/aws-security/runs/missing/delete-review").with(admin).with(csrf()).param("reviewId","review").param("confirmation","DELETE")).andExpect(status().isForbidden());
 }
 @org.springframework.boot.test.context.TestConfiguration(proxyBeanMethods=false)
 @org.springframework.stereotype.Controller
 static class ReportFixture {
  @org.springframework.web.bind.annotation.GetMapping("/fixture/aws-report")
  com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView report(){
   var model=new com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView("aws-report-fixture");
   var facts=new java.util.HashMap<String,String>();facts.put("Can delete AWS review","true");facts.put("AWS review deleted","false");facts.put("AWS review URL","https://app-00000000-0000-0000-0000-000000000000.securityagent.global.app.aws/as-space/code-reviews/cr-review");
   var status=new com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.Status("report-run","COMPLETE","Provider evidence imported","commit",null,"cr-review","cj-job",140,0,true,true,null,3,java.util.Map.of("HIGH",140),facts,java.util.List.of());
   var detail=new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation();detail.setViolationName("Local regex finding");detail.setSeverity("High");detail.setSeverityValue(1);detail.setFileName("src/App.java");detail.setLineNumber(12);detail.setMessage("Local scanner explanation");
   var local=com.tracelink.appsec.watchtower.core.scan.presentation.FindingPresentationModel.fromPullRequest(java.util.List.of(detail));
   var rule=new AwsSecurityRuleDto();rule.setId(1L);rule.setName("Security review");rule.setPriority(com.tracelink.appsec.watchtower.core.rule.RulePriority.HIGH);
   var snapshot=new AwsSecuritySnapshot(new com.tracelink.appsec.watchtower.core.scan.code.ScanExecutionContext("fixture",com.tracelink.appsec.watchtower.core.scan.code.CodeScanType.REPOSITORY,7,466,"Bitbucket","wt-test","master","commit",null,null,null,null),new AwsSecuritySettings.Profile("default","123456789012","us-east-1","space","arn:aws:iam::123456789012:role/testing","synthetic-fixture","","","watchtower"),rule.getExecutionIdentity(),rule.getName(),rule.getPriority(),rule.getRevision());
   var finding=software.amazon.awssdk.services.securityagent.model.Finding.builder().agentSpaceId("space").codeReviewId("review").codeReviewJobId("job").findingId("finding-one").riskType("COMMAND_INJECTION").riskLevel("HIGH").confidence("HIGH").codeLocations(software.amazon.awssdk.services.securityagent.model.CodeLocation.builder().filePath("src/App.java").lineStart(20).lineEnd(20).build()).build();
   var aws=com.tracelink.appsec.watchtower.core.scan.presentation.FindingPresentationModel.fromProvider("a".repeat(64),new AwsSecurityFindingMapper().map(finding,snapshot,"review","job")).withProviderDetailUrl("/fixture/aws-evidence");
   model.addObject("findings",local);model.addObject("providerStatuses",java.util.List.of(status));model.addObject("providerFindings",java.util.List.of(aws));model.addObject("providerPage",0);model.addObject("providerPages",3);model.addObject("providerImported",140);model.addObject("providerBase","/reposcan/report/7");model.addObject("providerIncomplete",false);model.addObject("workspaceFindings",java.util.List.of(aws,local.get(0)));
   return model.addScriptReference("/scripts/workspace-resizer.js").addScriptReference("/scripts/finding-workspace.js");
  }
 }
 @Test void secondActiveRequestIsRejectedAndUnknownModeIsInvalid()throws Exception{
  String body="{\"requestId\":\""+java.util.UUID.randomUUID()+"\",\"mode\":\"FULL\"}";
  mvc.perform(post("/aws-security/setup/tests").with(admin).with(csrf()).contentType("application/json").content(body)).andExpect(status().isOk());
  mvc.perform(post("/aws-security/setup/tests").with(admin).with(csrf()).contentType("application/json").content(body.replace("FULL","CLEAN"))).andExpect(status().isConflict());
  mvc.perform(post("/aws-security/setup/tests").with(admin).with(csrf()).contentType("application/json").content("{\"requestId\":\""+java.util.UUID.randomUUID()+"\",\"mode\":\"UNRESTRICTED\"}")).andExpect(status().isBadRequest());
 }
}
