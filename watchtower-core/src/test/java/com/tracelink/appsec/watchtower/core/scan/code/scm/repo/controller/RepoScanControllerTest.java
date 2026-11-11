package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.controller;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanService.PlanRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.QueueJobView;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanViewService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanViewService.RunSummary;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeExcerpts;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RepoScanControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private RepoScanViewService views;

	@MockitoBean
	private RepoScanService scans;

	@MockitoBean
	private RepoScanRepository scanRows;

	@MockitoBean
	private RepoScanReportService reports;

	@MockitoBean
	private RepoScanPlanRepository planRows;

	private RepoScanEntity scan;

	@BeforeEach
	public void setup() {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setApiLabel("bb");
		repo.setRepoName("payments-api");
		repo.setEnabled(true);
		repo.setLabels(List.of("pci"));
		repo.setTeam("checkout");
		repo.setLastCommitAt(System.currentTimeMillis());
		scan = new RepoScanEntity();
		scan.setRepository(repo);
		scan.setBranch("main");
		scan.setStatus(ScanStatus.DONE);
		scan.setCommitHash("abcdef1234567");
		scan.setReportKey("reports/x.json.gz");
		scan.setSeverityCounts(SeverityCounts.of(List.of(RulePriority.HIGH)));
		BDDMockito.when(views.scmIntegrations()).thenReturn(List.of("bb"));
		BDDMockito.when(views.recentRuns(ArgumentMatchers.anyInt()))
				.thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 50), 0));
		BDDMockito.when(views.recurringPlans(ArgumentMatchers.anyInt()))
				.thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 50), 0));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void theOldRepositoriesViewRedirectsToTheInventory() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan").param("view", "repositories")
				.param("source", "bb cloud").param("q", "pay"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(
						"/repositories?source=bb%20cloud&q=pay"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void scansOpenOnResultsForViewers() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scans/results?type=repository"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.SCAN_SUBMIT_NAME})
	public void submittersGetNewScanWithATargetPicker() throws Exception {
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/reposcan").param("view", "plans"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("New scan"),
						Matchers.containsString("data-scan-picker=\"true\""),
						Matchers.containsString("name=\"selector\""),
						// Repositories are chips; the ruleset is the searchable picker
						Matchers.containsString("data-scan-target-input"),
						Matchers.containsString("data-ruleset-picker"),
						Matchers.containsString("data-search=\"each repository own\""))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.SCAN_SUBMIT_NAME})
	public void resultsNewScanLinkOpensTheExistingDialog() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan")
				.param("view", "plans").param("new", "true"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString(
						"open=\"open\"")));
	}

	@Test
	@WithMockUser(username = "alice", authorities = CorePrivilege.SCAN_SUBMIT_NAME)
	public void aNewScanBySelectorStartsARun() throws Exception {
		RepoScanPlanEntity plan = BDDMockito.mock(RepoScanPlanEntity.class);
		BDDMockito.when(plan.getId()).thenReturn(4L);
		BDDMockito.when(scans.submit(ArgumentMatchers.any(), ArgumentMatchers.eq("alice")))
				.thenReturn(plan);

		mockMvc.perform(MockMvcRequestBuilders.post("/reposcan/submit")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("apiLabel", "bb").param("selector", "label:pci"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/reposcan/run/4/1"));

		ArgumentCaptor<PlanRequest> request = ArgumentCaptor.forClass(PlanRequest.class);
		BDDMockito.verify(scans).submit(request.capture(), ArgumentMatchers.eq("alice"));
		Assertions.assertEquals("label:pci", request.getValue().repoSelector());
	}

	@Test
	@WithMockUser(username = "alice", authorities = CorePrivilege.SCAN_SUBMIT_NAME)
	public void aRefusedScanFromTheInventoryGoesBackThere() throws Exception {
		BDDMockito.when(scans.submit(ArgumentMatchers.any(), ArgumentMatchers.eq("alice")))
				.thenThrow(new IllegalArgumentException("Choose at least one repository"));
		mockMvc.perform(MockMvcRequestBuilders.post("/reposcan/submit")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("apiLabel", "bb").param("repoIds", "1"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(
						"/repositories?source=bb"));
		mockMvc.perform(MockMvcRequestBuilders.post("/reposcan/submit")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("apiLabel", "bb").param("selector", "nothing*"))
				// A page that shows the message; plain /reposcan redirects again and drops it
				.andExpect(MockMvcResultMatchers.redirectedUrl("/reposcan?view=queue"))
				.andExpect(MockMvcResultMatchers.flash().attribute("failure", "Choose at least one repository"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_DASHBOARDS_NAME)
	public void thePageNeedsScanResults() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(username = "alice", authorities = CorePrivilege.SCAN_SUBMIT_NAME)
	public void submittingSelectedReposStartsARunAndOpensIt() throws Exception {
		RepoScanPlanEntity plan = BDDMockito.mock(RepoScanPlanEntity.class);
		BDDMockito.when(plan.getId()).thenReturn(9L);
		BDDMockito.when(scans.submit(ArgumentMatchers.any(), ArgumentMatchers.eq("alice")))
				.thenReturn(plan);

		mockMvc.perform(MockMvcRequestBuilders.post("/reposcan/submit")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("apiLabel", "bb").param("repoIds", "1", "2").param("rulesetId", "-1"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/reposcan/run/9/1"));

		ArgumentCaptor<PlanRequest> request = ArgumentCaptor.forClass(PlanRequest.class);
		BDDMockito.verify(scans).submit(request.capture(), ArgumentMatchers.eq("alice"));
		Assertions.assertEquals("id:1\nid:2", request.getValue().repoSelector());
		Assertions.assertNull(request.getValue().rulesetId());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_SUBMIT_NAME)
	public void postsNeedCsrf() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/reposcan/submit").param("apiLabel", "bb"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void reportViewsReplaceDialogsAndNeverCallUnverifiedRemovalsFixed() throws Exception {
		scan.setRuleCounts("{\"rule-a\":3,\"rule-b\":1}");
		RepoScanReport report = new RepoScanReport(1, 4, "bb", "payments-api", "main", "abcdef1234567", "Default",
				List.of(), List.of(new RepoScanReport.Fixed("old-rule", "src/Old.java", "gone")), List.of(), 0);
		BDDMockito.when(scanRows.findWithRepository(4L)).thenReturn(Optional.of(scan));
		BDDMockito.when(reports.getReport(scan)).thenReturn(Optional.of(report));
		BDDMockito.when(reports.codeFiles(report)).thenReturn(List.of());

		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/report/4").param("view", "byrule").param("search", "rule-b"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("<td>rule-b</td>"),
						Matchers.not(Matchers.containsString("<td>rule-a</td>")),
						Matchers.not(Matchers.containsString("ruleCountsDialog")))));
		// A legacy report has removed findings but no verified comparison: they are not "fixed".
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/report/4").param("view", "fixed"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("No longer reported (not verified as fixed)"),
						Matchers.containsString("src/Old.java"),
						Matchers.not(Matchers.containsString("fixedDialog")))));
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/report/4").param("view", "bogus"))
				.andExpect(MockMvcResultMatchers.status().isBadRequest());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void reportListsFindingsAndExportsCsv() throws Exception {
		RepoScanReport report = new RepoScanReport(1, 4, "bb", "payments-api", "main",
				"abcdef1234567", "Default",
				List.of(new RepoScanReport.Finding("hardcoded-token", "High", "src/App.java", 2,
						"Token found", "f1", true, false)),
				List.of(), List.of(), 1);
		BDDMockito.when(scanRows.findWithRepository(4L)).thenReturn(Optional.of(scan));
		BDDMockito.when(reports.getReport(scan)).thenReturn(Optional.of(report));
		BDDMockito.when(reports.codeFiles(report)).thenReturn(
				List.of(new RepoScanReportService.CodeFile("src/App.java", 1)));

		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/report/4"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("hardcoded-token"),
						Matchers.containsString("src/App.java:2"),
						// The PR report's Code section: the file, loading its code on open
						Matchers.containsString("id=\"wt-code-section\""),
						Matchers.containsString("data-file=\"src/App.java\""),
						Matchers.containsString("data-detail-source"),
						Matchers.containsString("/code?file=src/App.java\""),
						Matchers.containsString("hx-trigger=\"load\""),
						Matchers.containsString(">1 finding<"))));
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/report/4/export"))
				.andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith("text/csv"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString(
						"\"hardcoded-token\",\"High\",\"\",\"\",\"\",\"Token found\",\"src/App.java\",\"2\"")));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void codeIsOnlyServedForAFileOfTheReportWithSecretsMasked() throws Exception {
		RepoScanReport report = new RepoScanReport(1, 4, "bb", "payments-api", "main",
				"abcdef1234567", "Default",
				List.of(new RepoScanReport.Finding("generic-api-key", "High", "src/App.java", 2,
						"Secret found", "f1", true, true)),
				List.of(), List.of(), 1);
		BDDMockito.when(scanRows.findWithRepository(4L)).thenReturn(Optional.of(scan));
		BDDMockito.when(reports.getReport(scan)).thenReturn(Optional.of(report));
		BDDMockito.when(reports.codeFiles(report)).thenReturn(
				List.of(new RepoScanReportService.CodeFile("src/App.java", 1)));

		// A file the report's findings do not name is refused without touching the SCM
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/report/4/code")
				.param("file", "config/prod.env"))
				.andExpect(MockMvcResultMatchers.status().isNotFound());
		BDDMockito.verify(reports, BDDMockito.never()).codeFile(ArgumentMatchers.any(),
				ArgumentMatchers.any(), ArgumentMatchers.any());

		BDDMockito.when(reports.codeFile(scan, report, "src/App.java")).thenReturn(
				CodeExcerpts.of("src/App.java", "class App {\nString key = \"AKIA123\";\n}",
						java.util.Set.of(), java.util.Set.of(2), 1));
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/report/4/code")
				.param("file", "src/App.java"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString(CodeExcerpts.MASKED_LINE_TEXT),
						Matchers.containsString("wt-code-line-violation"),
						Matchers.not(Matchers.containsString("AKIA123")))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void codeOfAnExpiredReportIsNotFound() throws Exception {
		BDDMockito.when(scanRows.findWithRepository(4L)).thenReturn(Optional.of(scan));
		BDDMockito.when(reports.getReport(scan)).thenReturn(Optional.empty());
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/report/4/code")
				.param("file", "a.java"))
				.andExpect(MockMvcResultMatchers.status().isNotFound());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void queueShowsRepositoryNamesAndStatusChips() throws Exception {
		scan.setStatus(ScanStatus.NOT_STARTED);
		BDDMockito.when(views.queuedScans()).thenReturn(List.of(scan));
		var blocked = new com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.Status("earlier-run", "NEEDS_RECONCILIATION",
				"AWS operation unavailable (ValidationException); inspect stage and reconcile", "commit", null, null, null, 0, 0, false, false, null, 0, java.util.Map.of());
		BDDMockito.when(views.repositoryAdmissionBlocker()).thenReturn(
				new com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.RepositoryAdmissionBlocker(10, blocked));
		AsyncJobEntity job = BDDMockito.mock(AsyncJobEntity.class);
		BDDMockito.when(job.getType()).thenReturn(AsyncJobType.CATALOG_SYNC);
		BDDMockito.when(job.getStatus()).thenReturn(AsyncJobStatus.FAILED);
		BDDMockito.when(job.getError()).thenReturn("Bitbucket said no");
		List<QueueJobView> recent = List.of(QueueJobView.of(job));
		BDDMockito.when(views.recentJobs(QueueJobView.Filter.ALL)).thenReturn(recent);

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/reposcan")
				.param("view", "queue"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("payments-api @ main"),
						Matchers.containsString("Waiting for an earlier AWS assessment."),
						Matchers.containsString("/reposcan/report/10"),
						Matchers.containsString("AWS reported an invalid request"),
						Matchers.containsString("Scan #0"),
						Matchers.containsString(">Queued<"), Matchers.containsString(">Failed<"),
						Matchers.containsString("data-tip=\"Bitbucket said no\""),
						Matchers.not(Matchers.containsString(">FAILED<")),
						Matchers.not(Matchers.containsString("Nothing waiting or scanning")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void anIdleQueueIsOneLineAndAFailingIntegrationCheckIsAmber() throws Exception {
		AsyncJobEntity check = new AsyncJobEntity();
		check.setType(AsyncJobType.INTEGRATION_HEALTH);
		check.setStatus(AsyncJobStatus.DONE);
		check.setProgress("2 checked, 1 failing: Example (Amazon ECR)");
		AsyncJobEntity sync = new AsyncJobEntity();
		sync.setType(AsyncJobType.CATALOG_SYNC);
		sync.setStatus(AsyncJobStatus.DONE);
		sync.setProgress("1 repositories, 0 changed, 0 gone");
		BDDMockito.when(views.recentJobs(QueueJobView.Filter.CHECKS))
				.thenReturn(List.of(QueueJobView.of(check), QueueJobView.of(sync)));

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/reposcan")
				.param("view", "queue").param("jobs", "checks"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model().attribute("jobFilter", QueueJobView.Filter.CHECKS))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Nothing waiting or scanning"),
						Matchers.containsString(">1 of 2 failing<"),
						Matchers.containsString("href=\"/apisettings\""),
						Matchers.containsString("Example (Amazon ECR) failed its check."),
						Matchers.containsString(">1 repository<"),
						Matchers.not(Matchers.containsString("1 repositories")),
						Matchers.not(Matchers.containsString(">Completed<")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME, CorePrivilege.SCAN_ADMIN_NAME})
	public void everyTabCountsAndCanPauseScans() throws Exception {
		BDDMockito.when(views.countRuns()).thenReturn(6L);
		BDDMockito.when(views.countPlans()).thenReturn(0L);

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/reposcan").param("view", "plans"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString(">Results</a>"),
						Matchers.containsString("No recurring scans"),
						Matchers.containsString("aria-label=\"Pause scans\""),
						Matchers.containsString("Scanning on"),
						Matchers.not(Matchers.containsString("0–0 of 0")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME, CorePrivilege.SCAN_ADMIN_NAME})
	public void pausingReturnsToTheTabItWasPressedOn() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/reposcan/pause").param("paused", "true")
				.param("view", "plans").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/reposcan?view=plans"));
		mockMvc.perform(MockMvcRequestBuilders.post("/reposcan/pause").param("paused", "false")
				.param("view", "https://evil.example").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/reposcan?view=queue"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void runsOpenTheIndividualScanResultsPage() throws Exception {
		RepoScanPlanEntity plan = new RepoScanPlanEntity();
		plan.setName("Nightly");
		plan.setApiLabel("bb");
		plan.setRunCount(3);
		plan.setFrequency(PlanFrequency.DAILY);
		BDDMockito.when(views.recentRuns(1)).thenReturn(new PageImpl<>(
				List.of(new RunSummary(plan, Map.of(ScanStatus.DONE, 4L, ScanStatus.FAILED,
						1L))),
				PageRequest.of(1, 50), 51));

		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan")
				.param("view", "runs").param("page", "1"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scans/results?type=repository"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.SCAN_SUBMIT_NAME})
	public void plansShowTheDayAndConfirmDeleteOnce() throws Exception {
		RepoScanPlanEntity plan = new RepoScanPlanEntity();
		plan.setName("Weekly sweep");
		plan.setFrequency(PlanFrequency.WEEKLY);
		plan.setScheduleHour(2);
		plan.setScheduleDay(3);
		plan.setEnabled(true);
		BDDMockito.when(views.recurringPlans(0))
				.thenReturn(new PageImpl<>(List.of(plan), PageRequest.of(0, 50), 1));

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/reposcan")
				.param("view", "plans"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Weekly on Wednesday at 02:00 UTC"),
						Matchers.containsString(
								"data-confirm=\"Delete the plan Weekly sweep and its results?\""))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	public void schedulesNameTheirDay() {
		RepoScanPlanEntity plan = new RepoScanPlanEntity();
		plan.setFrequency(PlanFrequency.MONTHLY);
		plan.setScheduleHour(23);
		plan.setScheduleDay(15);
		Assertions.assertEquals("Monthly on day 15 at 23:00 UTC",
				RepoScanViewService.schedule(plan));
		plan.setFrequency(PlanFrequency.DAILY);
		plan.setScheduleHour(null);
		Assertions.assertEquals("Daily at 00:00 UTC", RepoScanViewService.schedule(plan));
		plan.setFrequency(PlanFrequency.WEEKLY);
		plan.setScheduleDay(7);
		Assertions.assertEquals("Weekly on Sunday at 00:00 UTC",
				RepoScanViewService.schedule(plan));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void runPageShowsSummaryChips() throws Exception {
		RepoScanPlanEntity plan = new RepoScanPlanEntity();
		plan.setName("Ad hoc");
		plan.setApiLabel("bb");
		scan.setEndDate(10L);
		RepoScanEntity failed = new RepoScanEntity();
		failed.setRepository(scan.getRepository());
		failed.setBranch("dev");
		failed.setStatus(ScanStatus.FAILED);
		failed.setEndDate(11L);
		BDDMockito.when(planRows.findById(9L)).thenReturn(Optional.of(plan));
		BDDMockito.when(scanRows.findRun(9L, 1)).thenReturn(List.of(scan, failed));

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/run/9/1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.not(Matchers.containsString("wt-stat-boxes")),
						Matchers.containsString("2 of 2 finished"),
						Matchers.containsString("wt-tone-danger"),
						Matchers.containsString("Not compared"))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}
}
