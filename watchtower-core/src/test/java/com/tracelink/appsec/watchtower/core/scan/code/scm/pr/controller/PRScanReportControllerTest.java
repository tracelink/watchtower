package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingAction;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingContext;
import com.tracelink.appsec.watchtower.core.scan.presentation.IFindingActionProvider;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRBypassRequestService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PullRequestBypassRequestEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.RequestSource;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.RequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRScanBypassException;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRScanBypassService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultCodeBlock;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultCodeLine;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultFile;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.verification.ILiveVerifier;
import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRScanReportControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private PRScanResultService mockScanResultService;

	@MockitoBean
	private ILiveVerifier mockVerifier;

	@MockitoBean
	private PRScanBypassService mockBypassService;

	@MockitoBean
	private IFindingActionProvider mockActionProvider;

	@MockitoBean
	private PRBypassRequestService mockRequestService;

	@MockitoBean
	private com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService mockRemoteAssessments;

	@BeforeEach
	public void stubBypassState() {
		BDDMockito.when(mockBypassService.stateFor(BDDMockito.anyLong(),
				BDDMockito.anyBoolean()))
				.thenReturn(BypassState.NONE);
		BDDMockito.when(mockRequestService.stateFor(BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(RequestState.NONE);
	}

	/////
	// Bypass requests (§4.17)
	/////

	private static PullRequestBypassRequestEntity pendingRequest(String requester) {
		PullRequestBypassRequestEntity request = new PullRequestBypassRequestEntity();
		request.setRequestedBy(requester);
		request.setReason("Release blocker");
		request.setCreatedAt(1_700_000_000_000L);
		return request;
	}

	@Test
	@WithMockUser(username = "lead", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testApproverIsToldACommentRequestNamesABitbucketUser() throws Exception {
		givenBypassState(new BypassState(true, null, null));
		PullRequestBypassRequestEntity request = pendingRequest("Dana Dev");
		request.setSource(RequestSource.PR_COMMENT);
		BDDMockito.when(mockRequestService.stateFor(1L, "lead"))
				.thenReturn(new RequestState(request, false));

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("in a pull request comment"),
						Matchers.containsString("data-bypass-request-source=\"pr-comment\"")))).andReturn();
		HtmlAssertions.assertHtmlIntegrity(mvcResult);
	}

	@Test
	@WithMockUser(username = "dev", authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testReportOffersItsOwnCsvAndSarifDownloads() throws Exception {
		givenBypassState(new BypassState(true, null, null));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("href=\"/scan/report/1/export?format=csv\""),
						Matchers.containsString("href=\"/scan/report/1/export?format=sarif\""))));
	}

	@Test
	@WithMockUser(username = "dev", authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testRequestDialogMentionsTheCommentCommand() throws Exception {
		givenBypassState(new BypassState(true, null, null));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("/watchtower bypass &lt;reason&gt;")));
	}

	@Test
	@WithMockUser(username = "dev", authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testViewerWithoutThePrivilegeCanRequestABypass() throws Exception {
		givenBypassState(new BypassState(true, null, null));

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("data-wt-dialog-target=\"#bypassDialog\""),
						Matchers.containsString("action=\"/scan/report/1/bypass/request\""),
						Matchers.containsString("Send request"),
						Matchers.not(Matchers.containsString("action=\"/scan/report/1/bypass\"")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(mvcResult);
		BDDMockito.verify(mockBypassService).stateFor(1L, true);
	}

	@Test
	@WithMockUser(username = "lead", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testApproverSeesThePendingRequestWithApproveAndDecline() throws Exception {
		givenBypassState(new BypassState(true, null, null));
		BDDMockito.when(mockRequestService.stateFor(1L, "lead"))
				.thenReturn(new RequestState(pendingRequest("dev"), false));

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("data-bypass-request=\"pending\""),
						Matchers.containsString("Release blocker"),
						Matchers.containsString("action=\"/scan/report/1/bypass/request/approve\""),
						Matchers.containsString("action=\"/scan/report/1/bypass/request/decline\""),
						Matchers.containsString("Review request"),
						Matchers.not(Matchers.containsString("/bypass/request/withdraw")),
						// One primary action: Approve, not also "Bypass blocking".
						Matchers.not(Matchers.containsString("action=\"/scan/report/1/bypass\"")),
						Matchers.not(Matchers.containsString(
								"action=\"/scan/report/1/bypass/request\"")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(mvcResult);
	}

	@Test
	@WithMockUser(username = "dev", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testRequesterCanOnlyWithdrawTheirRequest() throws Exception {
		givenBypassState(new BypassState(true, null, null));
		BDDMockito.when(mockRequestService.stateFor(1L, "dev"))
				.thenReturn(new RequestState(pendingRequest("dev"), true));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("action=\"/scan/report/1/bypass/request/withdraw\""),
						Matchers.not(Matchers.containsString("/bypass/request/approve")))));
	}

	@Test
	@WithMockUser(username = "dev", authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testRequestABypass() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/request")
				.param("reason", REASON)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString("requested")));
		BDDMockito.verify(mockRequestService).request(1L, "dev", REASON);
	}

	@Test
	@WithMockUser(username = "dev", authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testRefusedRequestShowsTheReason() throws Exception {
		BDDMockito.when(mockRequestService.request(1L, "dev", REASON))
				.thenThrow(new PRScanBypassException("Rotate it first."));

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/request")
				.param("reason", REASON)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION, "Rotate it first."));
	}

	@Test
	@WithMockUser(username = "lead", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testApproveARequest() throws Exception {
		BDDMockito.when(mockRequestService.approve(1L, "lead")).thenReturn(true);

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/request/approve")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.flash().attributeExists(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION));
	}

	@Test
	@WithMockUser(username = "lead", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testDecisionsFromTheRequestsListReturnToTheList() throws Exception {
		BDDMockito.when(mockRequestService.approve(1L, "lead")).thenReturn(true);

		for (String action : new String[] {"approve", "decline"}) {
			mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/request/" + action)
					.param("from", "requests")
					.with(SecurityMockMvcRequestPostProcessors.csrf()))
					.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/bypasses?view=requests"));
		}
	}

	@Test
	@WithMockUser(username = "lead", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testAnUnknownReturnTargetGoesBackToTheReport() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/request/decline")
				.param("from", "https://evil.example.invalid")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/report/1"));
	}

	@Test
	@WithMockUser(username = "dev", authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testWithdrawFromTheRequestsListReturnsToTheList() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/request/withdraw")
				.param("from", "requests")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/bypasses?view=requests"));
	}

	@Test
	@WithMockUser(username = "dev", authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testApproveAndDeclineNeedThePrivilege() throws Exception {
		for (String action : new String[] {"approve", "decline"}) {
			mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/request/" + action)
					.with(SecurityMockMvcRequestPostProcessors.csrf()))
					.andExpect(MockMvcResultMatchers.status().isForbidden());
		}
		BDDMockito.verifyNoInteractions(mockRequestService);
	}

	@Test
	@WithMockUser(username = "lead", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testDeclineARequestWithANote() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/request/decline")
				.param("note", "Fix it instead")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION, "Bypass request declined."));
		BDDMockito.verify(mockRequestService).decline(1L, "lead", "Fix it instead");
	}

	@Test
	@WithMockUser(username = "dev", authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testWithdrawARequest() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/request/withdraw")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION, "Bypass request withdrawn."));
		BDDMockito.verify(mockRequestService).withdraw(1L, "dev");
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetReport() throws Exception {
		String id = "1";

		PRScanResult result = BDDMockito.mock(PRScanResult.class);

		BDDMockito.when(mockScanResultService.getScanResultForScanId(id)).thenReturn(result);

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/" + id))
				.andExpect(MockMvcResultMatchers.model().attribute("result", result));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetReportRendersCodeSectionAfterFindings() throws Exception {
		// Guards the layout this page was rebuilt for: the code belongs in its own section BELOW
		// the findings table, once per file, with the flagged line highlighted - not in a column
		// repeated inside every finding row. Nothing else in the suite asserts on this markup, so
		// without this a refactor could silently put it back.
		String id = "1";

		PRScanResultViolation violation = new PRScanResultViolation();
		violation.setViolationName("Test Rule");
		violation.setSeverity(RulePriority.HIGH.getName());
		violation.setSeverityValue(RulePriority.HIGH.getPriority());
		violation.setFileName("foo/bar.java");
		violation.setLineNumber(2);
		violation.setMessage("guidance");

		PRScanResultCodeBlock block = new PRScanResultCodeBlock(Arrays.asList(
				new PRScanResultCodeLine(1, "line one", false),
				new PRScanResultCodeLine(2, "line two", true)));

		PRScanResult result = new PRScanResult();
		result.setId(1L);
		result.setPrId("123");
		result.setDisplayName("PR 123");
		result.setAuthor("author");
		result.setDate(LocalDateTime.now());
		result.setPrLink("https://example.invalid/pr/123");
		result.setApiLabel("api");
		result.setRepoName("repo");
		result.setViolations(Arrays.asList(violation));
		result.setMcrFindings(Collections.emptyList());
		result.setCodeFiles(Arrays.asList(
				PRScanResultFile.withSource("foo/bar.java", Arrays.asList(block), 1)));

		BDDMockito.when(mockScanResultService.getScanResultForScanId(id)).thenReturn(result);

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/" + id))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("id=\"wt-code-section\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("wt-code-line wt-code-line-violation")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("wt-sev wt-sev-1")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.stringContainsInOrder("wt-findings", "wt-code-section")))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(mvcResult);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.SCAN_ADMIN_NAME})
	public void testGetReportKeepsPerformanceSummaryConcise() throws Exception {
		PRScanResult result = new PRScanResult();
		result.setId(1L);
		result.setDisplayName("PR 123");
		result.setDate(LocalDateTime.now());
		result.setPrLink("https://example.invalid/pr/123");
		result.setViolations(Collections.emptyList());
		result.setMcrFindings(Collections.emptyList());
		result.setCodeFiles(Collections.emptyList());
		result.setPerformanceComplete(true);
		result.setTotalDurationMs(5000L);
		result.setQueueWaitDurationMs(100L);
		result.setSourcePreparationDurationMs(1000L);
		result.setScannerExecutionDurationMs(2500L);
		result.setResultProcessingDurationMs(500L);
		result.setScmReportingDurationMs(750L);
		result.setPersistenceDurationMs(100L);
		result.setCleanupDurationMs(50L);
		result.setChangedFileCount(3);
		result.setScanScope("CHANGED_FILES");
		result.setSourceStrategy("INDIVIDUAL_FILES");
		BDDMockito.when(mockScanResultService.getScanResultForScanId("1")).thenReturn(result);

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString(
								"Administrator timing details"))))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("RegexScanner"))))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("INDIVIDUAL_FILES"))))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("wt-info-trigger"))))
				// The total is a timer chip in the facts line; the stage timings are the strip's
				// proportional bar, labelled once (UAT walkthrough, 2026-10-15).
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("data-tip=\"Total time from start to finish\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("wt-timing-bar__seg--analysis")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("Security analysis")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("Start through cleanup"))));
	}

	private static com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.Status awsStatus(
			String state, boolean complete, String jobId, Map<String, String> facts) {
		return new com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.Status("run-1", state, null,
				"c24f7f66c116156f0ee8692a2f96f71ce26d86b8", "84d065f0fad835e3394eb1c500143ec22b6a2866",
				jobId == null ? null : "cr-f692003f-b177-4b0e-b843-c073bbfa940f", jobId, complete ? 11 : 0, 0, true,
				complete, 30, 1, Map.of("CRITICAL", 3, "HIGH", 3, "MEDIUM", 5), facts,
				List.of(new com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.ProgressStep(
						"PREPARING", "COMPLETED", null, null),
						new com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.ProgressStep(
								"FINALIZING", "NOT_STARTED", null, null)));
	}

	private static PRScanResult awsReportResult() {
		PRScanResult result = new PRScanResult();
		result.setId(1L);
		result.setDisplayName("PR 123");
		result.setDate(LocalDateTime.now());
		result.setViolations(Collections.emptyList());
		result.setMcrFindings(Collections.emptyList());
		result.setCodeFiles(Collections.emptyList());
		return result;
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME, "AWS Security Administration",
			"Repository Settings View"})
	public void testAwsDialogShowsTilesSeverityIdsStepsAndOperatorIcons() throws Exception {
		BDDMockito.when(mockScanResultService.getScanResultForScanId("1")).thenReturn(awsReportResult());
		BDDMockito.when(mockRemoteAssessments.status("pull_request", 1L)).thenReturn(List.of(awsStatus("COMPLETE", true,
				"cj-c039bc14-e140-420b-a7d7-1ce32926f386", Map.of("Started", "2026-10-29T09:00:00Z",
						"Finished", "2026-10-29T09:09:48Z", "Source files", "25", "Patch bytes", "1792"))));
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("wt-pd__tiles")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("9m 48s")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString(
						"class=\"localizetime\" data-time-style=\"short\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("start to finish")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("25 files")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("patch 1.8 KB")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("data-sev=\"CRITICAL\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Review cr-f692003f")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("data-copy-text=\"cj-c039bc14-e140-420b-a7d7-1ce32926f386\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Preparing")))
				// A completed job completed every step, even one the saved snapshot still lists as not started
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Finalizing")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(Matchers.containsString("radio_button_unchecked"))))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("/aws-security/runs/run-1/reconcile")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(Matchers.containsString("AWS did not finish"))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testAwsDialogExplainsAFailedRunWithoutIdsAndHidesOperatorIconsFromViewers() throws Exception {
		BDDMockito.when(mockScanResultService.getScanResultForScanId("1")).thenReturn(awsReportResult());
		BDDMockito.when(mockRemoteAssessments.status("pull_request", 1L)).thenReturn(List.of(awsStatus("FAILED", false,
				null, Map.of("Started", "2026-10-29T09:00:00Z", "Finished", "2026-10-29T09:00:05Z", "Source files", "0"))));
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("AWS did not finish, so this result is not an all-scanner pass.")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("never started")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("not prepared")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("No AWS job was started")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(Matchers.containsString("/aws-security/runs/run-1/reconcile"))));
	}

	/////
	// Verify live
	/////

	private static final String VERIFY_PRIVILEGE = "Test Verify Live";

	private static PRScanResult resultWith(PRScanResultViolation... violations) {
		PRScanResult result = new PRScanResult();
		result.setId(1L);
		result.setDisplayName("PR 123");
		result.setDate(LocalDateTime.now());
		result.setPrLink("https://example.invalid/pr/123");
		result.setViolations(Arrays.asList(violations));
		result.setMcrFindings(Collections.emptyList());
		result.setCodeFiles(Collections.emptyList());
		return result;
	}

	private static PRScanResultViolation violation(long id, String rule) {
		PRScanResultViolation violation = new PRScanResultViolation();
		violation.setViolationId(id);
		violation.setViolationName(rule);
		violation.setSeverity(RulePriority.HIGH.getName());
		violation.setSeverityValue(RulePriority.HIGH.getPriority());
		violation.setFileName("config.yml");
		violation.setLineNumber(3);
		violation.setMessage("guidance");
		return violation;
	}

	private void stubVerifier() {
		BDDMockito.when(mockVerifier.getPrivilegeName()).thenReturn(VERIFY_PRIVILEGE);
		BDDMockito.when(mockVerifier.supports("Secrets: token")).thenReturn(true);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME, VERIFY_PRIVILEGE})
	public void testReportOffersVerifyLiveOnSupportedFindingsAndListsLiveFirst()
			throws Exception {
		stubVerifier();
		BDDMockito.when(mockVerifier.getStatuses(BDDMockito.anyCollection()))
				.thenReturn(Map.of(7L, LiveVerificationStatus.LIVE));
		BDDMockito.when(mockScanResultService.getScanResultForScanId("1")).thenReturn(
				resultWith(violation(6L, "Other: rule"), violation(7L, "Secrets: token")));

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("data-verify-id=\"7\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("data-verify-id=\"6\""))))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("Live - rotate now")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("action=\"/scan/report/1/verify\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.stringContainsInOrder("data-verify-id=\"7\"",
								"Other: rule")))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(mvcResult);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testReportShowsStatusButCannotRequestWithoutThePrivilege() throws Exception {
		stubVerifier();
		BDDMockito.when(mockVerifier.getStatuses(BDDMockito.anyCollection()))
				.thenReturn(Map.of());
		BDDMockito.when(mockScanResultService.getScanResultForScanId("1"))
				.thenReturn(resultWith(violation(7L, "Secrets: token")));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("data-verify-can-request=\"false\"")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testReportStillRendersWhenVerificationStatusFails() throws Exception {
		stubVerifier();
		BDDMockito.when(mockVerifier.getStatuses(BDDMockito.anyCollection()))
				.thenThrow(new IllegalStateException("db down"));
		BDDMockito.when(mockScanResultService.getScanResultForScanId("1"))
				.thenReturn(resultWith(violation(7L, "Secrets: token")));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("data-verify-id"))));
	}

	@Test
	@WithMockUser(username = "alice",
			authorities = {CorePrivilege.SCAN_RESULTS_NAME, VERIFY_PRIVILEGE})
	public void testRequestVerificationQueuesItAndReturnsToTheReport() throws Exception {
		BDDMockito.when(mockVerifier.getPrivilegeName()).thenReturn(VERIFY_PRIVILEGE);
		BDDMockito.when(mockVerifier.request(1L, 7L, "alice"))
				.thenReturn(LiveVerificationStatus.PENDING);

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/verify")
				.param("violationId", "7")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.flash().attributeExists(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION));
		// The report's own scan id, so the service can check the finding belongs to it.
		BDDMockito.verify(mockVerifier).request(1L, 7L, "alice");
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testRequestVerificationNeedsThePrivilege() throws Exception {
		BDDMockito.when(mockVerifier.getPrivilegeName()).thenReturn(VERIFY_PRIVILEGE);

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/verify")
				.param("violationId", "7")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.flash().attributeExists(
						WatchtowerModelAndView.FAILURE_NOTIFICATION));
		BDDMockito.verify(mockVerifier, BDDMockito.never())
				.request(BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME, VERIFY_PRIVILEGE})
	public void testRequestVerificationOfAnUnsupportedFindingFails() throws Exception {
		BDDMockito.when(mockVerifier.getPrivilegeName()).thenReturn(VERIFY_PRIVILEGE);
		BDDMockito.when(mockVerifier.request(BDDMockito.anyLong(), BDDMockito.anyLong(),
				BDDMockito.any()))
				.thenThrow(new IllegalArgumentException("Unknown finding"));

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/verify")
				.param("violationId", "7")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION, "Unknown finding"));
	}

	/////
	// PR-level bypass (§4.12)
	/////

	private static final String REASON = "Hotfix for an outage";

	private void givenBypassState(BypassState state) {
		BDDMockito.when(mockScanResultService.getScanResultForScanId("1"))
				.thenReturn(resultWith(violation(7L, "Secrets: token")));
		BDDMockito.when(mockBypassService.stateFor(BDDMockito.eq(1L), BDDMockito.anyBoolean()))
				.thenReturn(state);
	}

	private static ActiveBypass activeBypass() {
		return new ActiveBypass("alice", REASON, 1000L, Set.of());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testReportOffersBypassWhileBlocked() throws Exception {
		givenBypassState(new BypassState(true, null, null));

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("data-wt-dialog-target=\"#bypassDialog\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("action=\"/scan/report/1/bypass\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("maxlength=\"1000\"")))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(mvcResult);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testReportShowsBlockingButNoBypassWithoutThePrivilege() throws Exception {
		givenBypassState(new BypassState(true, null, null));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("data-bypass-status=\"blocked\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("action=\"/scan/report/1/bypass\""))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testReportExplainsWhyBypassIsDisabled() throws Exception {
		givenBypassState(new BypassState(true, "A secret is verified live. Rotate it first.",
				null));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("Rotate it first.")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("data-bypass-refusal")))
				// The refusal is the dialog's content: no form and no disabled button.
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("id=\"bypassForm\""))))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString(" disabled"))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testReportShowsActiveBypassWithRevoke() throws Exception {
		givenBypassState(new BypassState(false, null, activeBypass()));

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("data-bypass-status=\"bypassed\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString(REASON)))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("alice")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("action=\"/scan/report/1/bypass/revoke\"")))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(mvcResult);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testReportShowsActiveBypassWithoutRevokeToOthers() throws Exception {
		givenBypassState(new BypassState(false, null, activeBypass()));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString(REASON)))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("/bypass/revoke"))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testReportShowsNoBypassSectionWhenNothingApplies() throws Exception {
		givenBypassState(BypassState.NONE);

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("data-bypass-status"))));
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testBypassSavesAndReturnsToTheReport() throws Exception {
		BDDMockito.when(mockBypassService.bypass(1L, "alice", REASON)).thenReturn(true);

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass")
				.param("reason", REASON)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.flash().attributeExists(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION));
		BDDMockito.verify(mockBypassService).bypass(1L, "alice", REASON);
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testBypassSavedButScmNotUpdatedSaysSo() throws Exception {
		BDDMockito.when(mockBypassService.bypass(1L, "alice", REASON)).thenReturn(false);

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass")
				.param("reason", REASON)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("could not be updated")));
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testRefusedBypassShowsTheReason() throws Exception {
		BDDMockito.when(mockBypassService.bypass(1L, "alice", REASON))
				.thenThrow(new PRScanBypassException("Rotate it first."));

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass")
				.param("reason", REASON)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION, "Rotate it first."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testBypassNeedsThePrivilege() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass")
				.param("reason", REASON)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
		BDDMockito.verify(mockBypassService, BDDMockito.never())
				.bypass(BDDMockito.anyLong(), BDDMockito.any(), BDDMockito.any());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testBypassAlsoNeedsScanResults() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass")
				.param("reason", REASON)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(username = "bob", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testRevokeRescansAndReturnsToTheReport() throws Exception {
		BDDMockito.when(mockBypassService.revoke(1L, "bob")).thenReturn(true);

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/revoke")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString("rescan")));
		BDDMockito.verify(mockBypassService).revoke(1L, "bob");
	}

	@Test
	@WithMockUser(username = "bob", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testRevokeWithoutRescanSaysBlockingResumesOnPush() throws Exception {
		BDDMockito.when(mockBypassService.revoke(1L, "bob")).thenReturn(false);

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/revoke")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString("next push")));
	}

	@Test
	@WithMockUser(username = "bob", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testRefusedRevokeShowsTheReason() throws Exception {
		BDDMockito.when(mockBypassService.revoke(1L, "bob"))
				.thenThrow(new PRScanBypassException("No active bypass on this pull request."));

		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/revoke")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"No active bypass on this pull request."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testRevokeNeedsThePrivilege() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/report/1/bypass/revoke")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
		BDDMockito.verify(mockBypassService, BDDMockito.never())
				.revoke(BDDMockito.anyLong(), BDDMockito.any());
	}

	/////
	// Module actions on a finding (§4.15)
	/////

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testReportShowsAModuleActionOnItsFinding() throws Exception {
		PRScanResult result = resultWith(violation(7L, "Secrets: token"));
		result.setApiLabel("bb");
		result.setRepoName("payments");
		BDDMockito.when(mockScanResultService.getScanResultForScanId("1")).thenReturn(result);
		BDDMockito.when(mockActionProvider.actionFor(BDDMockito.any(), BDDMockito.any()))
				.thenReturn(Optional.of(new FindingAction("Allowlist…",
						"/betterleaks/allowlist?rule=token")));

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString(
						"data-action-url=\"/betterleaks/allowlist?rule=token\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString(
						"data-action-label=\"Allowlist…\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString(
						"data-detail-action")))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(mvcResult);

		ArgumentCaptor<FindingContext> context = ArgumentCaptor.forClass(FindingContext.class);
		BDDMockito.verify(mockActionProvider).actionFor(context.capture(), BDDMockito.any());
		Assertions.assertEquals(new FindingContext("bb", "payments", "Secrets: token",
				"config.yml", 3), context.getValue());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testReportStillRendersWhenAnActionProviderFails() throws Exception {
		BDDMockito.when(mockScanResultService.getScanResultForScanId("1"))
				.thenReturn(resultWith(violation(7L, "Secrets: token")));
		BDDMockito.when(mockActionProvider.actionFor(BDDMockito.any(), BDDMockito.any()))
				.thenThrow(new IllegalStateException("module broken"));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("data-action-url="))));
	}

	/////
	// Latest report of a PR (the PR comment's link, §4.14)
	/////

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testLatestReportRedirectsToTheNewestScan() throws Exception {
		PullRequestContainerEntity container = new PullRequestContainerEntity();
		List<PullRequestScanEntity> scans = new ArrayList<>();
		for (long id : new long[] {4L, 9L, 6L}) {
			PullRequestScanEntity scan = new PullRequestScanEntity();
			ReflectionTestUtils.setField(scan, "id", id);
			scans.add(scan);
		}
		ReflectionTestUtils.setField(container, "scans", scans);
		BDDMockito.when(mockScanResultService.getPullRequestByLabelRepoAndId("bb cloud",
				"payments", "17")).thenReturn(container);

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/latest")
				.param("apiLabel", "bb cloud").param("repo", "payments").param("prId", "17"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/report/9"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testLatestReportOfAnUnknownPullRequest() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/latest")
				.param("apiLabel", "bb").param("repo", "payments").param("prId", "17"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"No scan found for that pull request."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME})
	public void testLatestReportNeedsScanResults() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/latest")
				.param("apiLabel", "bb").param("repo", "payments").param("prId", "17"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetReportUnknown() throws Exception {
		String id = "1";

		BDDMockito.when(mockScanResultService.getScanResultForScanId(id))
				.thenReturn(null);

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/" + id))
				.andExpect(MockMvcResultMatchers.model().attribute("result",
						Matchers.emptyOrNullString()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, "Unknown ID"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan"));
	}
}
