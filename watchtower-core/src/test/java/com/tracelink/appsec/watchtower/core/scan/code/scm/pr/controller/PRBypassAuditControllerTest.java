package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassAudit;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassRequestStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRBypassAuditService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRBypassRequestService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PullRequestBypassEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PullRequestBypassRequestEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.RepoBypassCount;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.RequestSource;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRBypassAuditControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private PRBypassAuditService auditService;

	@MockitoBean
	private PRBypassRequestService requestService;

	private static PullRequestBypassEntity bypass(String prId, long scanId, String by,
			String reason, String revokedBy) {
		PullRequestBypassEntity bypass = new PullRequestBypassEntity();
		bypass.setApiLabel("bb");
		bypass.setRepoName("payments");
		bypass.setPrId(prId);
		bypass.setScanId(scanId);
		bypass.setBypassedBy(by);
		bypass.setReason(reason);
		bypass.setCreatedAt(1_700_000_000_000L);
		bypass.setFindings(Set.of());
		if (revokedBy != null) {
			bypass.revoke(revokedBy, 1_700_000_100_000L);
		}
		return bypass;
	}

	private void givenAudit() {
		PullRequestBypassEntity active = bypass("17", 5L, "alice", "Hotfix <b>now</b>", null);
		PullRequestBypassEntity revoked = bypass("18", 6L, "carol", "Fixture key", "bob");
		BDDMockito.when(auditService.audit()).thenReturn(new BypassAudit(List.of(active),
				List.of(revoked, active), List.of(new RepoBypassCount("bb", "payments", 2))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void testReasonCategoryIsShownNotRecordedOnlyWhenMissing() throws Exception {
		PullRequestBypassEntity accepted = bypass("17", 5L, "alice", "Known", null);
		accepted.setReasonCode(
				com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassReasonCode.ACCEPTED_RISK);
		PullRequestBypassEntity old = bypass("18", 6L, "carol", "Old one", null);
		BDDMockito.when(auditService.audit()).thenReturn(new BypassAudit(List.of(accepted, old),
				List.of(accepted, old), List.of()));

		String html = mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses"))
				.andExpect(MockMvcResultMatchers.status().isOk()).andReturn().getResponse()
				.getContentAsString();

		Assertions.assertEquals(1, StringUtils.countMatches(html, "Accepted risk"));
		Assertions.assertEquals(1, StringUtils.countMatches(html, "Not recorded"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void testAllViewIsOneTableOfRecentBypasses() throws Exception {
		givenAudit();

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Active (1)"),
						Matchers.containsString("href=\"/scan/report/5\""),
						Matchers.containsString("href=\"/scan/report/6\""),
						Matchers.containsString("Hotfix &lt;b&gt;now&lt;/b&gt;"),
						Matchers.containsString("Revoked by bob"),
						Matchers.not(Matchers.containsString("data-repo-bypass-count")),
						Matchers.not(Matchers.containsString("class=\"card")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
		Assertions.assertEquals(1, StringUtils.countMatches(
				result.getResponse().getContentAsString(), "<table"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void testActiveViewListsOnlyActiveBypasses() throws Exception {
		givenAudit();

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses").param("view", "active"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("href=\"/scan/report/5\""),
						Matchers.not(Matchers.containsString("href=\"/scan/report/6\"")),
						Matchers.containsString("aria-current=\"page\""))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void testRepositoryViewCountsBypassesPerRepository() throws Exception {
		givenAudit();

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses").param("view", "repos"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("data-repo-bypass-count=\"2\""),
						Matchers.not(Matchers.containsString("href=\"/scan/report/5\"")))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void testUnknownViewShowsAll() throws Exception {
		givenAudit();

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses").param("view", "<x>"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("href=\"/scan/report/6\"")));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void testEmptyAudit() throws Exception {
		BDDMockito.when(auditService.audit())
				.thenReturn(new BypassAudit(List.of(), List.of(), List.of()));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("No pull request has been bypassed yet.")));
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses").param("view", "active"))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("No pull request is bypassed right now.")));
	}

	/////
	// Bypass requests
	/////

	private static PullRequestBypassRequestEntity request(String prId, long scanId,
			String requester, RequestSource source) {
		PullRequestBypassRequestEntity request = new PullRequestBypassRequestEntity();
		request.setApiLabel("bb");
		request.setRepoName("payments");
		request.setPrId(prId);
		request.setScanId(scanId);
		request.setRequestedBy(requester);
		request.setReason("Fixture key <i>only</i>");
		request.setCreatedAt(1_700_000_000_000L);
		request.setSource(source);
		return request;
	}

	/** One pending request by dev on scan 7, one declined request by dev on scan 8. */
	private void givenRequests() {
		givenAudit();
		PullRequestBypassRequestEntity declined =
				request("20", 8L, "dev", RequestSource.WATCHTOWER);
		declined.decide(BypassRequestStatus.DECLINED, "lead", 1_700_000_100_000L, "Fix it");
		BDDMockito.when(requestService.recentRequests()).thenReturn(List.of(
				request("19", 7L, "dev", RequestSource.WATCHTOWER), declined));
	}

	@Test
	@WithMockUser(username = "lead", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testApproverCanApproveOrDeclineAPendingRequestFromTheList() throws Exception {
		givenRequests();

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses")
				.param("view", "requests"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Requests (1)"),
						Matchers.containsString("href=\"/scan/report/7\""),
						Matchers.containsString("href=\"/scan/report/8\""),
						Matchers.containsString("Fixture key &lt;i&gt;only&lt;/i&gt;"),
						Matchers.containsString(
								"action=\"/scan/report/7/bypass/request/approve?from=requests\""),
						Matchers.containsString(
								"action=\"/scan/report/7/bypass/request/decline?from=requests\""),
						// The decided request has no actions, only its outcome.
						Matchers.not(Matchers.containsString("/scan/report/8/bypass/request")),
						Matchers.containsString("Declined by lead"),
						Matchers.containsString("Fix it"),
						Matchers.not(Matchers.containsString("/bypass/request/withdraw")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(username = "dev", authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void testRequesterCanWithdrawButNotApprove() throws Exception {
		givenRequests();

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses").param("view", "requests"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString(
								"action=\"/scan/report/7/bypass/request/withdraw?from=requests\""),
						Matchers.not(Matchers.containsString("/bypass/request/approve")),
						Matchers.not(Matchers.containsString("/bypass/request/decline")))));
	}

	@Test
	@WithMockUser(username = "lead", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testApproverCannotApproveTheirOwnRequestFromTheList() throws Exception {
		givenAudit();
		BDDMockito.when(requestService.recentRequests()).thenReturn(
				List.of(request("19", 7L, "LEAD", RequestSource.WATCHTOWER)));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses").param("view", "requests"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("/scan/report/7/bypass/request/withdraw"),
						Matchers.not(Matchers.containsString("/bypass/request/approve")))));
	}

	@Test
	@WithMockUser(username = "lead", authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.PR_SCAN_BYPASS_NAME})
	public void testCommentRequestsSayTheNameIsABitbucketOne() throws Exception {
		givenAudit();
		BDDMockito.when(requestService.recentRequests()).thenReturn(
				List.of(request("19", 7L, "Dana Dev", RequestSource.PR_COMMENT)));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses").param("view", "requests"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("data-bypass-request-source=\"pr-comment\""),
						Matchers.containsString("/scan/report/7/bypass/request/approve"))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void testPendingRequestsOpenTheRequestsViewByDefault() throws Exception {
		givenRequests();

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses"))
				.andExpect(MockMvcResultMatchers.model().attribute("view", "requests"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void testNoRequests() throws Exception {
		givenAudit();

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses").param("view", "requests"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Requests (0)"),
						Matchers.containsString("Nobody has asked for a bypass yet."))));
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses"))
				.andExpect(MockMvcResultMatchers.model().attribute("view", "all"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_SUBMIT_NAME)
	public void testNeedsScanResults() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/bypasses"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}
}
