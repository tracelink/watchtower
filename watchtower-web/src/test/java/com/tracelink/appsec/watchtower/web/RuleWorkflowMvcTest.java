package com.tracelink.appsec.watchtower.web;

import static org.junit.jupiter.api.Assertions.*;
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
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.persistence.*;

/** Real HTML, authorization and bound JPA paging for the dedicated rule workflows. */
@SpringBootTest(properties={"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
        "spring.datasource.url=jdbc:h2:mem:uat-review;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@AutoConfigureMockMvc @ActiveProfiles("dev") @Transactional
class RuleWorkflowMvcTest {
 @MockitoBean com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
 @Autowired MockMvc mvc; @Autowired RuleRepository rules; @Autowired LedgerRepository records;
 private long id; private String revision;
 private final org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor viewer = user("viewer").authorities(()->"Ruleset View",()->"Scan Results View");
 private final org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor editor = user("editor").authorities(()->"Rule Modify",()->"Scan Results View");
 @BeforeEach void seed() {
  var dto=new RegexCustomRuleDto();dto.setName("Review <script> fixture");dto.setAuthor("reviewer");dto.setMessage("Review match");dto.setExternalUrl("https://example.test/rule");dto.setPriority(RulePriority.HIGH);dto.setRegexPattern("unsafe|risky");dto.setFileExtension("");
  var rule=rules.saveAndFlush(dto.toEntity());id=rule.getId();revision=rule.toDto().getRevision();
 }
 @Test void healthDistinguishesMissingEvidenceAndRequiresAccess() throws Exception {
  mvc.perform(get("/rules/"+id+"/health").with(viewer)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("No eligible execution projection")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("No run records")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Too little data to judge")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("0 of 6 needed")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Insufficient data/coverage"))))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Review &lt;script&gt; fixture")));
  mvc.perform(get("/rules/"+id+"/health").with(user("reader").authorities(()->"Ruleset View"))).andExpect(status().isForbidden());
  var contribution=new RuleMetricScanEntity("repository",1L,"c".repeat(64),id,revision,"regex",System.currentTimeMillis(),0L,0L,0L,null,"UNKNOWN",null);contribution.engineStatus="RAN";records.insert(contribution);records.flush();
  mvc.perform(get("/rules/"+id+"/health").with(viewer)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("A relevant engine completed successfully")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Ran, no matches")));
 }
 @Test void reviewsPageIsAddressableCompleteAndEscaped() throws Exception {
  for(int i=0;i<56;i++)records.insert(new RuleReviewItemEntity(java.util.UUID.randomUUID().toString(),id,revision,"owner","OPEN",i==0?"literal%":"Investigate","<img src=x>",null,null,null,null,"",1L,(long)i,1L));
  records.flush();
  mvc.perform(get("/rules/"+id+"/reviews?page=2").with(viewer)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("51–56 of 56")));
  mvc.perform(get("/rules/"+id+"/reviews").param("search","%").with(viewer)).andExpect(status().isOk())
   // One literal match (the % is escaped, not a wildcard); a single page shows no pager.
   .andExpect(content().string(org.hamcrest.Matchers.containsString("literal%")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("wt-pagination__status"))));
  mvc.perform(get("/rules/"+id+"/reviews?pageSize=101").with(viewer)).andExpect(status().isBadRequest());
  mvc.perform(get("/rules/"+id+"/reviews").with(editor)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-rule-review-form")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-review-new")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("In review")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString(">IN_REVIEW<"))));
  // An older revision is one amber chip, and new reviews go on the current revision.
  mvc.perform(get("/rules/"+id+"/reviews?revision="+"b".repeat(64)).with(editor)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-review-historical")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("data-review-new"))))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("data-rule-review-form"))));
 }
 @Test void candidatePageAndPreparationDoNotClaimTestsHaveRun() throws Exception {
  mvc.perform(get("/rules/"+id+"/candidates").with(editor)).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("data-rule-candidates-page")));
  mvc.perform(get("/rules/"+id+"/candidates").with(viewer)).andExpect(status().isForbidden());
  mvc.perform(get("/rule/candidates/rule/"+id+"/preparation").with(editor)).andExpect(status().isOk()).andExpect(jsonPath("$.suiteUsable").value(false));
  mvc.perform(get("/rule/candidates/rule/"+id+"/page?pageSize=101").with(editor)).andExpect(status().isBadRequest());
 }
 @Test void evidenceIsRevisionBoundAndRevokedAccessCannotAttachScanData() throws Exception {
  records.insert(new FindingFeedbackEntity("f".repeat(64),"repository",1L,"k",id,revision,true,1L,"FALSE_POSITIVE","OTHER","<img src=x>","reviewer",2L,1L));records.flush();
  mvc.perform(get("/rules/"+id+"/reviews/evidence?kind=finding").with(viewer)).andExpect(status().isOk())
   .andExpect(jsonPath("$.content[0].id").value("f".repeat(64))).andExpect(jsonPath("$.totalElements").value(1));
  mvc.perform(get("/rules/"+id+"/reviews/evidence?kind=finding&revision="+"b".repeat(64)).with(viewer)).andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(0));
  mvc.perform(get("/rules/"+id+"/reviews/evidence?kind=finding").with(user("no-scan").authorities(()->"Rule Modify"))).andExpect(status().isForbidden());
  String body="{\"ruleId\":"+id+",\"revision\":\""+revision+"\",\"owner\":\"reviewer\",\"status\":\"OPEN\",\"reason\":\"Check\",\"recommendation\":\"Inspect\",\"evidenceType\":\"finding\",\"evidenceId\":\""+"f".repeat(64)+"\",\"outcome\":\"\",\"version\":0}";
  mvc.perform(post("/rule/evidence/reviews").with(user("no-scan").authorities(()->"Rule Modify")).with(csrf()).contentType("application/json").content(body)).andExpect(status().isForbidden());
  mvc.perform(post("/rule/evidence/reviews").with(editor).with(csrf()).contentType("application/json").content(body.replace("f".repeat(64),"e".repeat(64)))).andExpect(status().isBadRequest());
  var result=mvc.perform(post("/rule/evidence/reviews").with(editor).with(csrf()).contentType("application/json").content(body)).andExpect(status().isOk()).andReturn();
  String reviewId=new com.fasterxml.jackson.databind.ObjectMapper().readTree(result.getResponse().getContentAsString()).get("id").asText();
  mvc.perform(get("/rules/"+id+"/reviews?reviewId="+reviewId).with(editor)).andExpect(status().isOk());
  mvc.perform(get("/rules/"+id+"/reviews/"+reviewId+"/history").with(viewer)).andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(1));
 }
 @Test void savedReportPageShowsCompleteRowsAndLabelsLegacyLimitations() throws Exception {
  var facts=new com.tracelink.appsec.watchtower.core.rule.report.RuleReviewReport.RuleFacts(id,"<img src=x>","regex",RulePriority.HIGH,RuleState.ACTIVE,null,null,null,java.util.Set.of(),java.util.Map.of(),java.util.Map.of(),0,revision);
  var summary=com.tracelink.appsec.watchtower.core.rule.report.RuleReviewReport.build(java.util.List.of(facts),com.tracelink.appsec.watchtower.core.rule.report.RuleReviewReport.Catalog.load(),java.time.LocalDate.now());
  String reportId=java.util.UUID.randomUUID().toString();
  var report=new com.tracelink.appsec.watchtower.core.rule.report.RuleReviewReportEntity(reportId,null,"MANUAL","reviewer",0,System.currentTimeMillis(),new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(summary));report.withCompleteItems();records.insert(report);
  records.insert(com.tracelink.appsec.watchtower.core.rule.report.RuleReviewReportItemEntity.from(reportId,0,com.tracelink.appsec.watchtower.core.rule.report.RuleReviewReport.attention(java.util.List.of(facts),java.time.LocalDate.now()).getFirst()));records.flush();
  mvc.perform(get("/rules/review-reports?reportId="+reportId+"&view=attention").with(viewer)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-report-item")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("Confirmed noise")))
   .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString(">CONFIRMED_NOISE<"))))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("&lt;img src=x&gt;")));
  mvc.perform(get("/rules/review-reports?reportId="+reportId+"&view=settings").with(viewer)).andExpect(status().isOk());
  mvc.perform(get("/rules/review-reports?reportId="+reportId).with(user("unauthorized"))).andExpect(status().isForbidden());
  String legacy=java.util.UUID.randomUUID().toString();summary.put("attention_truncated",true);
  records.insert(new com.tracelink.appsec.watchtower.core.rule.report.RuleReviewReportEntity(legacy,null,"MANUAL","historical",0,1,new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(summary)));records.flush();
  mvc.perform(get("/rules/review-reports?reportId="+legacy+"&view=attention").with(viewer)).andExpect(status().isOk())
   .andExpect(content().string(org.hamcrest.Matchers.containsString("rows kept")))
   .andExpect(content().string(org.hamcrest.Matchers.containsString("data-report-legacy")));
 }
}
