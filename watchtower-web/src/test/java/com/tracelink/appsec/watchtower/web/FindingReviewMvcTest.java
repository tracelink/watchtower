package com.tracelink.appsec.watchtower.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService;

/** Ordinary application contract tests: actual paging queries, HTML, permissions and optimistic feedback saves. */
@SpringBootTest(properties = {"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
        "spring.datasource.url=jdbc:h2:mem:uat-review;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@AutoConfigureMockMvc @ActiveProfiles("dev") @Transactional
class FindingReviewMvcTest {
    @MockitoBean com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    private final org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor reviewer =
            user("reviewer").authorities(() -> "Finding Feedback", () -> "Scan Results View");
    private static final String QUERY = "scanType=pull_request&scanId=1&findingKey=1";

    @BeforeEach void fixtures() {
        jdbc.update("INSERT INTO pull_request_container(container_id,last_review_date,resolved,api_label,author,source_branch) VALUES (1,0,FALSE,'uat','fixture','main')");
        jdbc.update("INSERT INTO pull_request_scans(scan_entity_id,container_id,submit_date,start_date,end_date,status,blocked,source_size_bytes,total_duration_ms,queue_wait_duration_ms,source_preparation_duration_ms,scanner_execution_duration_ms,result_processing_duration_ms,scm_reporting_duration_ms,persistence_duration_ms,cleanup_duration_ms,performance_complete,changed_file_count) VALUES (1,1,0,0,1700000001000,'Done',FALSE,0,0,0,0,0,0,0,0,0,FALSE,0)");
        for (int id = 1; id <= 60; id++) jdbc.update("INSERT INTO pull_request_violations(vio_entity_id,scan_entity_id,violation_name,file_path,line_number,severity) VALUES (?,1,?,?,?,'High')",
                id, id == 1 ? "<img src=x>" : id == 3 ? "Percent%Rule" : "Rule", "src/App.java", id);
    }

    @Test void pageIdentifiesOccurrenceEscapesEvidenceAndConservativelyReturnsToReport() throws Exception {
        var result = mvc.perform(get("/finding-feedback/review?" + QUERY).with(reviewer).param("returnTo", "//evil.test"))
                .andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("Review finding")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("&lt;img src=x&gt;")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("line 1")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("href=\"/scan/report/1\""))).andReturn();
        assertFalse(result.getResponse().getContentAsString().contains("href=\"//evil.test"));
        mvc.perform(get("/finding-feedback/review?scanType=pull_request&scanId=999&findingKey=1").with(reviewer)).andExpect(status().isNotFound());
        mvc.perform(get("/finding-feedback/review?" + QUERY).with(user("viewer").authorities(() -> "Scan Results View"))).andExpect(status().isForbidden());
    }

    @Test void fullBacklogAndHistoryRemainReachableWithBoundSearchAndPageLimits() throws Exception {
        mvc.perform(get("/finding-feedback/review/items?" + QUERY + "&page=2").with(reviewer))
                .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(60))
                .andExpect(jsonPath("$.content.length()").value(10)).andExpect(jsonPath("$.content[0].key").value("51"));
        mvc.perform(get("/finding-feedback/review/items?" + QUERY).param("search", "%").with(reviewer))
                .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(1)).andExpect(jsonPath("$.content[0].key").value("3"));
        for (String paging : new String[]{"&pageSize=101", "&page=-1", "&page=2147483647"})
            mvc.perform(get("/finding-feedback/review/items?" + QUERY + paging).with(reviewer)).andExpect(status().isBadRequest());
        String occurrence = FindingFeedbackService.occurrenceKey("pull_request", 1, "1");
        for (int i = 0; i < 28; i++) jdbc.update("INSERT INTO finding_feedback_audit(occurrence_key,judgment,disposition,explanation,reviewer,changed_at) VALUES (?,'TRUE_POSITIVE','ACCEPTED_RISK','Reason','reviewer',?)", occurrence, 1700000000000L + i);
        mvc.perform(get("/finding-feedback/review/history?" + QUERY + "&page=1").with(reviewer))
                .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(28)).andExpect(jsonPath("$.content.length()").value(3));
    }

    @Test void savingKeepsTheExistingCsrfVersionAndIndependentJudgmentContracts() throws Exception {
        String body = "{\"scanType\":\"pull_request\",\"scanId\":1,\"findingKeys\":[\"1\"],\"judgment\":\"TRUE_POSITIVE\",\"disposition\":\"ACCEPTED_RISK\",\"explanation\":\"Reviewed\",\"versions\":{\"1\":0}}";
        mvc.perform(post("/finding-feedback").with(reviewer).contentType("application/json").content(body)).andExpect(status().isForbidden());
        mvc.perform(post("/finding-feedback").with(reviewer).with(csrf()).contentType("application/json").content(body)).andExpect(status().isOk());
        mvc.perform(post("/finding-feedback").with(reviewer).with(csrf()).contentType("application/json").content(body)).andExpect(status().isConflict());
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM finding_feedback", Integer.class));
        assertEquals("TRUE_POSITIVE", jdbc.queryForObject("SELECT judgment FROM finding_feedback", String.class));
        assertEquals("ACCEPTED_RISK", jdbc.queryForObject("SELECT disposition FROM finding_feedback", String.class));
    }
}
