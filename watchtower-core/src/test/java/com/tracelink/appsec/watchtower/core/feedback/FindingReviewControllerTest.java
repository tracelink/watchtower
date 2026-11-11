package com.tracelink.appsec.watchtower.core.feedback;

import java.util.Optional;
import java.util.Set;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeExcerpts;
import com.tracelink.appsec.watchtower.core.scan.code.report.ScanReportReader;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

/** Review finding page (UAT #8, walkthrough 2026-10-15): renders the redesign and loads source. */
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
class FindingReviewControllerTest {
	@Autowired
	private MockMvc mockMvc;
	@MockitoBean
	private FindingReviewService reviews;
	@MockitoBean
	private PRScanResultService prResults;
	@MockitoBean
	private ScanReportReader scanReports;

	private static FindingReviewService.Workspace workspace(String type) {
		var item = new FindingReviewService.Item("7", "test (slackwebhook)", "High",
				"src/main/java/App.java", 14, 31L, "abc123", 2, "UNKNOWN", "ACTION_REQUIRED", null);
		return new FindingReviewService.Workspace(type, 158707, item, "/scan/report/158707", true, null, 0);
	}

	@Test
	@WithMockUser(authorities = {"Scan Results View", "Finding Feedback", "Rule Modify"})
	void pageShowsTheFindingCardChoicesAndASourceLink() throws Exception {
		BDDMockito.when(reviews.workspace("pull_request", 158707, "7", 0, null)).thenReturn(workspace("pull_request"));
		BDDMockito.when(reviews.scannerModule("pull_request", 158707, "7")).thenReturn("Regex");

		mockMvc.perform(MockMvcRequestBuilders.get("/finding-feedback/review")
				.param("scanType", "pull_request").param("scanId", "158707").param("findingKey", "7"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("App.java:14")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("value=\"UNKNOWN\" checked")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("value=\"ACTION_REQUIRED\" checked")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString(
						"hx-get=\"/finding-feedback/review/source?scanType=pull_request&amp;scanId=158707&amp;findingKey=7\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Rule health")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Found by Regex")));
	}

	@Test
	@WithMockUser(authorities = {"Scan Results View", "Finding Feedback"})
	void theSourcePanelSaysSecretsAreMaskedOnlyWhenASecretsScannerRan() throws Exception {
		BDDMockito.when(reviews.workspace("pull_request", 158707, "7", 0, null)).thenReturn(workspace("pull_request"));
		var request = MockMvcRequestBuilders.get("/finding-feedback/review")
				.param("scanType", "pull_request").param("scanId", "158707").param("findingKey", "7");

		BDDMockito.when(scanReports.secretsScannerRan("pull_request", 158707)).thenReturn(false);
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("data-review-source")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(Matchers.containsString("Secrets masked"))));

		BDDMockito.when(scanReports.secretsScannerRan("pull_request", 158707)).thenReturn(true);
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Secrets masked")));
	}

	@Test
	@WithMockUser(authorities = {"Scan Results View", "Finding Feedback"})
	void uploadFindingsHaveNoSourcePanel() throws Exception {
		BDDMockito.when(reviews.workspace("upload", 158707, "7", 0, null)).thenReturn(workspace("upload"));

		mockMvc.perform(MockMvcRequestBuilders.get("/finding-feedback/review")
				.param("scanType", "upload").param("scanId", "158707").param("findingKey", "7"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(Matchers.containsString("data-review-source"))))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(Matchers.containsString("Rule health"))));
	}

	@Test
	@WithMockUser(authorities = {"Scan Results View", "Finding Feedback"})
	void sourceRendersTheFlaggedLinesOrSaysUnavailable() throws Exception {
		BDDMockito.when(prResults.reviewSource(158707, 7)).thenReturn(Optional.of(new PRScanResultService.ReviewSource(
				CodeExcerpts.of("src/main/java/App.java", "a\nb\nsecret = 1\nd", Set.of(), Set.of(3), 1),
				"https://bitbucket.org/ws/repo/pull-requests/58/diff#chg-src/main/java/App.java")));
		mockMvc.perform(MockMvcRequestBuilders.get("/finding-feedback/review/source")
				.param("scanType", "pull_request").param("scanId", "158707").param("findingKey", "7"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("wt-code-line-violation")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(Matchers.containsString("secret = 1"))))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Whole file in the pull request")));

		BDDMockito.when(prResults.reviewSource(158707, 8)).thenReturn(Optional.empty());
		mockMvc.perform(MockMvcRequestBuilders.get("/finding-feedback/review/source")
				.param("scanType", "pull_request").param("scanId", "158707").param("findingKey", "8"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Source unavailable")));

		mockMvc.perform(MockMvcRequestBuilders.get("/finding-feedback/review/source")
				.param("scanType", "upload").param("scanId", "158707").param("findingKey", "7"))
				.andExpect(MockMvcResultMatchers.status().isBadRequest());
	}
}
