package com.tracelink.appsec.watchtower.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestMCRStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

/** The MCR report is drawn like the pull request report: a status chip, fact chips, and the status form in a dialog. */
@SpringBootTest(properties = {"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
		"spring.datasource.url=jdbc:h2:mem:mcr-report-ui;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class McrReportMvcTest {
	@MockitoBean
	com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
	@MockitoBean
	PRScanResultService results;
	@Autowired
	MockMvc mvc;

	@BeforeEach
	void scan() {
		var result = new PRScanResult();
		result.setId(58);
		result.setDisplayName("wt-test-58");
		result.setAuthor("Jane Doe");
		result.setApiLabel("BitBucket");
		result.setPrLink("https://bitbucket.example/pull-requests/58");
		result.setDate(LocalDateTime.of(2026, 10, 8, 21, 10, 35));
		result.setMcrStatus(PullRequestMCRStatus.PENDING_REVIEW);
		result.setMcrFindings(List.of());
		result.setViolations(List.of());
		when(results.getScanResultForScanId("58")).thenReturn(result);
	}

	@Test
	void aReviewerSeesTheStatusChipTheFactChipsAndTheStatusDialog() throws Exception {
		mvc.perform(get("/scan/mcr/report/58").with(user("reviewer").authorities(() -> "Scan Results View", () -> "Scan MCR Modify")))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("wt-report-head__status")))
				.andExpect(content().string(containsString("Pending Review")))
				.andExpect(content().string(containsString("Waiting for a reviewer to start.")))
				.andExpect(content().string(containsString("View pull request")))
				.andExpect(content().string(containsString("Scan · 0 findings")))
				.andExpect(content().string(containsString("0 MCR matches")))
				.andExpect(content().string(containsString("data-wt-dialog-open=\"#mcrStatusDialog\"")))
				.andExpect(content().string(containsString("id=\"mcrStatusDialog\"")))
				.andExpect(content().string(containsString("action=\"/scan/mcr/report/58/setstatus\"")))
				.andExpect(content().string(containsString("name=\"mcrstatus\"")))
				.andExpect(content().string(not(containsString("wt-report-bar"))));
	}

	@Test
	void aViewerSeesTheStatusButCannotChangeIt() throws Exception {
		mvc.perform(get("/scan/mcr/report/58").with(user("viewer").authorities(() -> "Scan Results View")))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Pending Review")))
				.andExpect(content().string(not(containsString("Update status"))))
				.andExpect(content().string(not(containsString("mcrStatusDialog"))));
	}
}
