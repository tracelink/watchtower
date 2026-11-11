package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.ArrayList;
import java.util.List;

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
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
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
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanResultsService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanResultsService.Kind;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanService;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryInventoryService.Counts;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryInventoryService.Row;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryInventoryService.Tab;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RepositoryControllerTest {

	private static final String PR_URL = "/repository/" + CodeScanType.PULL_REQUEST.getTypeName();
	private static final String CODE_URL = "/repositories";

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private RepositoryService mockRepoService;

	@MockitoBean
	private RepositoryInventoryService mockInventory;

	@MockitoBean
	private RulesetService mockRulesetService;

	@MockitoBean
	private RepoScanService mockScans;

	@MockitoBean
	private RepositoryCsvService mockCsv;

	@MockitoBean
	private RepositoryPullRequestService mockPullRequests;

	@MockitoBean
	private CodeScanResultsService mockResults;

	@BeforeEach
	public void setup() {
		BDDMockito.when(mockResults.page(ArgumentMatchers.any(Kind.class), ArgumentMatchers.anyInt(),
				ArgumentMatchers.any(RepositoryEntity.class)))
				.thenReturn(new PagedResult<>(List.of(), 0, 20, 0, 0));
		BDDMockito.when(mockInventory.counts(ArgumentMatchers.any(), ArgumentMatchers.any(),
				ArgumentMatchers.anyBoolean()))
				.thenReturn(new Counts(3, 1, 1, 2, null));
		BDDMockito.when(mockInventory.ago(ArgumentMatchers.any())).thenReturn("never");
		BDDMockito.when(mockInventory.labels(ArgumentMatchers.any(), ArgumentMatchers.any()))
				.thenReturn(List.of("pci"));
	}

	///////////////////
	// The inventory
	///////////////////
	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void scanResultViewersSeeStatusesAndReasonsButNoActions() throws Exception {
		givenTabs(new Tab("alpha-bb", false), new Tab("zeta-bb", false, true));
		givenRows("alpha-bb", page(3, 0, row("payments-api", RepoStatus.PAUSED,
				"Scanning is paused: pull requests are not scanned and plans skip it.")));

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get(PR_URL))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model().attribute("activeSource", "alpha-bb"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Code repositories"),
						Matchers.containsString("payments-api"), Matchers.containsString(">Paused<"),
						Matchers.containsString("plans skip it"),
						Matchers.containsString("class=\"wt-count-badge\">3<"),
						Matchers.containsString(">Failing<"),
						Matchers.not(Matchers.containsString("wt-repo-select")),
						Matchers.not(Matchers.containsString("Sync now")),
						Matchers.not(Matchers.containsString("Scan selected")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.REPO_SETTINGS_VIEW_NAME)
	public void repositorySettingsViewersCanOpenItToo() throws Exception {
		givenTabs(new Tab("alpha-bb", false));
		givenRows("alpha-bb", page(1, 0, row("repo-a", RepoStatus.ACTIVE, "ok")));
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL))
				.andExpect(MockMvcResultMatchers.status().isOk());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.REPO_SETTINGS_MODIFY_NAME})
	public void aSyncInProgressIsShownAndItsButtonCannotBePressed() throws Exception {
		givenTabs(new Tab("alpha-bb", false));
		givenRows("alpha-bb", page(1, 0, row("repo-a", RepoStatus.ACTIVE, "ok")));
		BDDMockito.when(mockScans.isSyncRunning()).thenReturn(true);

		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("data-sync-running"),
						Matchers.containsString("is-busy"),
						Matchers.containsString("Syncing the repository list"),
						Matchers.matchesRegex("(?s).*<button[^>]*form=\"repoSyncForm\"[^>]*\\sdisabled[^>]*>.*"))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.REPO_SETTINGS_MODIFY_NAME})
	public void withNoSyncRunningTheSyncButtonIsPlain() throws Exception {
		givenTabs(new Tab("alpha-bb", false));
		givenRows("alpha-bb", page(1, 0, row("repo-a", RepoStatus.ACTIVE, "ok")));
		BDDMockito.when(mockScans.isSyncRunning()).thenReturn(false);

		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.not(Matchers.containsString("data-sync-running")),
						Matchers.not(Matchers.containsString("is-busy")),
						Matchers.containsString("Sync now"))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_DASHBOARDS_NAME)
	public void otherUsersCannot() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.REPO_SETTINGS_MODIFY_NAME, CorePrivilege.SCAN_SUBMIT_NAME})
	public void editorsGetSelectionSyncScanAndTheDialogs() throws Exception {
		givenTabs(new Tab("alpha-bb", false), new Tab("old-bb", true));
		// A full page of two out of three, so "select all matching" has more to offer
		givenRows("alpha-bb", new PageImpl<>(List.of(row("payments-api", RepoStatus.ACTIVE,
				"ok"), row("legacy", RepoStatus.GONE, "Not found")), PageRequest.of(0, 2), 3));

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get(PR_URL))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("wt-repo-select"),
						Matchers.containsString("Sync now"),
						Matchers.containsString("Scan selected"),
						Matchers.containsString("id=\"repoScanDialog\""),
						Matchers.containsString("id=\"repoBulkEditDialog\""),
						// Popups (UAT walkthrough, 2026-10-16): the searchable ruleset picker,
						// criticality and When as buttons, Keep defaults and the import drop zone
						Matchers.containsString("data-ruleset-picker"),
						Matchers.containsString("name=\"rulesetId\""),
						Matchers.containsString("type=\"radio\" name=\"frequency\" value=\"WEEKLY\""),
						Matchers.containsString("data-scan-day=\"WEEKLY\""),
						Matchers.containsString("type=\"radio\" name=\"criticality\" value=\"\""),
						Matchers.containsString("Only what you change is saved"),
						Matchers.containsString("Up to 5,000 rows · 1 MB"),
						Matchers.containsString("Blank cells clear values"),
						Matchers.not(Matchers.containsString("Hour (UTC)")),
						Matchers.containsString("data-edit-selection"),
						Matchers.not(Matchers.containsString("Set ruleset")),
						Matchers.not(Matchers.containsString("Edit profile")),
						Matchers.containsString("data-edit-name=\"payments-api\""),
						Matchers.containsString("aria-label=\"Clear the selection\""),
						Matchers.containsString("aria-label=\"Scan payments-api\""),
						Matchers.not(Matchers.containsString("aria-label=\"Scan legacy\"")),
						// A deleted integration's tab carries a red dot (its name for screen
						// readers) instead of a link counting its orphans
						Matchers.containsString(">Deleted<"),
						Matchers.containsString("data-tab-state=\"deleted\""),
						Matchers.not(Matchers.containsString("2 orphaned")),
						Matchers.containsString("1 gone"), Matchers.containsString("1 paused"),
						Matchers.containsString("Add repository"),
						Matchers.containsString("id=\"repoEditDialog\""),
						Matchers.not(Matchers.containsString("aria-label=\"Edit payments-api\"")),
						Matchers.not(Matchers.containsString("data-clean-up")),
						Matchers.containsString("href=\"/repositories/0\""),
						Matchers.containsString("form=\"repoDeleteForm\""),
						Matchers.containsString("Select all 3 matching"),
						Matchers.containsString("/repository/pull_request/export?source=alpha-bb"),
						Matchers.not(Matchers.containsString("maxlength")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void theSearchTakesTokensStatusAndLabelAndKeepsThemInPageLinks() throws Exception {
		givenTabs(new Tab("alpha-bb", false), new Tab("zeta-bb", false));
		BDDMockito.when(mockInventory.rows(ArgumentMatchers.eq(CodeScanType.PULL_REQUEST),
				ArgumentMatchers.eq("zeta-bb"), ArgumentMatchers.any(),
				ArgumentMatchers.any(Pageable.class)))
				.thenReturn(page(120, 0, rows(50)));

		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL).param("source", "zeta-bb")
				.param("q", "  pay team:checkout ").param("status", "inactive")
				.param("label", "pci"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model().attribute("baseUrl",
						CODE_URL + "?source=zeta-bb&q=pay%20team:checkout&status=inactive"
								+ "&label=pci"))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("120 of 3 repositories")));

		ArgumentCaptor<RepositoryFilter> filter = ArgumentCaptor.forClass(RepositoryFilter.class);
		BDDMockito.verify(mockInventory).rows(ArgumentMatchers.eq(CodeScanType.PULL_REQUEST),
				ArgumentMatchers.eq("zeta-bb"), filter.capture(),
				ArgumentMatchers.any(Pageable.class));
		Assertions.assertEquals("pay", filter.getValue().text());
		Assertions.assertEquals("checkout", filter.getValue().team());
		Assertions.assertEquals(RepoStatus.INACTIVE, filter.getValue().status());
		Assertions.assertEquals("pci", filter.getValue().label());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void anUnknownSourceFallsBackToTheFirstTab() throws Exception {
		givenTabs(new Tab("alpha-bb", false), new Tab("zeta-bb", false));
		givenRows("alpha-bb", page(1, 0, row("repo-a", RepoStatus.ACTIVE, "ok")));
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL).param("source", "missing"))
				.andExpect(MockMvcResultMatchers.model().attribute("activeSource", "alpha-bb"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void aSourceDifferingOnlyInCaseOpensThatTab() throws Exception {
		// A repository stored under "zeta-BB" links here with its own spelling
		givenTabs(new Tab("alpha-bb", false), new Tab("zeta-bb", false));
		givenRows("zeta-bb", page(1, 0, row("repo-z", RepoStatus.ACTIVE, "ok")));
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL).param("source", "ZETA-bb"))
				.andExpect(MockMvcResultMatchers.model().attribute("activeSource", "zeta-bb"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void emptyTabsAndUnmatchedFiltersSayDifferentThings() throws Exception {
		givenTabs(new Tab("alpha-bb", false));
		givenRows("alpha-bb", page(0, 0));
		BDDMockito.when(mockInventory.counts(ArgumentMatchers.any(), ArgumentMatchers.any(),
				ArgumentMatchers.anyBoolean()))
				.thenReturn(new Counts(0, 0, 0, 0, null));
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("No repositories yet.")));

		BDDMockito.when(mockInventory.counts(ArgumentMatchers.any(), ArgumentMatchers.any(),
				ArgumentMatchers.anyBoolean()))
				.thenReturn(new Counts(5, 0, 0, 0, null));
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL).param("status", "gone"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("No repository matches these filters."),
						Matchers.containsString(">Clear<"))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void noIntegrationsShowsTheEmptyState() throws Exception {
		givenTabs();
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("No repository integrations are configured.")));
		BDDMockito.verify(mockInventory, BDDMockito.never()).rows(ArgumentMatchers.any(),
				ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void aPageBeyondTheLastRedirectsKeepingTheFilter() throws Exception {
		givenTabs(new Tab("alpha-bb", false));
		BDDMockito.when(mockInventory.rows(ArgumentMatchers.any(), ArgumentMatchers.any(),
				ArgumentMatchers.any(), ArgumentMatchers.any(Pageable.class)))
				.thenReturn(new PageImpl<>(List.of(), PageRequest.of(7, 50), 60));
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL).param("q", "bill")
				.param("page", "7"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(
						CODE_URL + "?source=alpha-bb&q=bill&page=1"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void aDataFailureShowsARecoverablePage() throws Exception {
		BDDMockito.when(mockInventory.tabs(CodeScanType.PULL_REQUEST))
				.thenThrow(new DataAccessResourceFailureException("database unavailable"));
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"Repository configuration is temporarily unavailable. Please try again."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.REPO_SETTINGS_MODIFY_NAME, CorePrivilege.SCAN_SUBMIT_NAME})
	public void imageRepositoriesHaveNoSyncOrScan() throws Exception {
		BDDMockito.when(mockInventory.tabs(ImageScanType.CONTAINER))
				.thenReturn(List.of(new Tab("ecr", false)));
		BDDMockito.when(mockInventory.rows(ArgumentMatchers.eq(ImageScanType.CONTAINER),
				ArgumentMatchers.eq("ecr"), ArgumentMatchers.any(),
				ArgumentMatchers.any(Pageable.class)))
				.thenReturn(page(1, 0, row("api", RepoStatus.ACTIVE, "ok")));
		mockMvc.perform(MockMvcRequestBuilders.get("/repository/container"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Image repositories"),
						Matchers.containsString("data-edit-selection"),
						Matchers.not(Matchers.containsString("Sync now")),
						Matchers.not(Matchers.containsString("Scan selected")),
						Matchers.not(Matchers.containsString("Last scan")))));
	}

	///////////////////
	// Sync and bulk changes
	///////////////////
	@Test
	@WithMockUser(username = "alice", authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void syncQueuesAndReturnsToTheTab() throws Exception {
		givenTabs(new Tab("alpha-bb", false));
		BDDMockito.when(mockScans.requestSync("alice")).thenReturn(List.of());
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/sync")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("source", "alpha-bb"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL + "?source=alpha-bb"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"A repository sync is already running"));
		BDDMockito.verify(mockScans).requestSync("alice");
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void syncNeedsRepositorySettingsModify() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/sync")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
		BDDMockito.verify(mockScans, BDDMockito.never()).requestSync(ArgumentMatchers.any());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void bulkEditChangesTheSelectedAndKeepsTheFilter() throws Exception {
		givenTabs(new Tab("bb", false));
		BDDMockito.when(mockRepoService.editMany(List.of(1L, 2L), 4L, null, null, null, null))
				.thenReturn(2);
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/bulk")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("action", "edit")
				.param("repoIds", "1", "2").param("rulesetId", "4").param("source", "bb")
				.param("status", "paused"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL
						+ "?source=bb&status=paused"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION, "Updated 2 repositories"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void bulkEditKeepsWhatIsLeftBlank() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/bulk")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("action", "edit")
				.param("repoIds", "1").param("rulesetId", "").param("team", " ")
				.param("owner", "").param("labels", "pci, sox").param("criticality", "")
				.param("source", "bb"))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection());
		BDDMockito.verify(mockRepoService).editMany(List.of(1L), null, null, null,
				List.of("pci", "sox"), null);
	}

	@Test
	@WithMockUser(username = "alice", authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void aDeletedIntegrationsRepositoriesCanBeCleanedUpAndItsTabGoes() throws Exception {
		givenTabs(new Tab("bb", false), new Tab("API1", true));
		BDDMockito.when(mockInventory.deleteAllOf("API1", "alice"))
				.thenReturn(new RepositoryService.DeleteResult(6, 0));

		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/clean-up")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("source", "API1"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Deleted API1 and its 6 repositories"));
	}

	@Test
	@WithMockUser(username = "alice", authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void aLiveIntegrationIsNeverCleanedUpAndBusyOnesStay() throws Exception {
		givenTabs(new Tab("bb", false), new Tab("API1", true));

		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/clean-up")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("source", "bb"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"Only a deleted integration's repositories can be cleaned up"));
		BDDMockito.verify(mockInventory, BDDMockito.never()).deleteAllOf(ArgumentMatchers.any(),
				ArgumentMatchers.any());

		BDDMockito.when(mockInventory.deleteAllOf("API1", "alice"))
				.thenReturn(new RepositoryService.DeleteResult(4, 2));
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/clean-up")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("source", "API1"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL + "?source=API1"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION, Matchers.startsWith(
								"Deleted 4 repositories; 2 repositories being scanned")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME,
			CorePrivilege.REPO_SETTINGS_MODIFY_NAME})
	public void aDeletedIntegrationsTabOffersOnlyTheCleanUp() throws Exception {
		givenTabs(new Tab("bb", false), new Tab("API1", true));
		givenRows("API1", page(6, 0, row("old-repo", RepoStatus.ORPHANED, "deleted")));
		BDDMockito.when(mockInventory.counts(ArgumentMatchers.any(), ArgumentMatchers.eq("API1"),
				ArgumentMatchers.anyBoolean())).thenReturn(new Counts(6, 0, 0, 6, null));

		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL).param("source", "API1"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						// One red line says what happened and offers the clean-up
						Matchers.containsString("data-orphan-line"),
						Matchers.containsString("API1 was deleted."),
						Matchers.containsString("Its 6 repositories are orphaned"),
						Matchers.containsString("Delete API1&#39;s 6 repositories"),
						Matchers.containsString("form=\"repoCleanUpForm\""),
						Matchers.containsString("Delete all 6 repositories of the deleted integration API1"),
						Matchers.not(Matchers.containsString("Sync now")),
						Matchers.not(Matchers.containsString("Add repository")))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void bulkNeedsRepositorySettingsModify() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/bulk")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("action", "edit")
				.param("repoIds", "1").param("rulesetId", "2"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void bulkRefusalsAreShown() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/bulk")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("action", "edit")
				.param("source", "bb"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"Choose at least one repository"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void postsNeedCsrf() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/bulk").param("action", "edit"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(username = "alice", authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void editSavesOneRepositoryAndAMissingScanningSwitchPausesIt() throws Exception {
		givenTabs(new Tab("bb", false));
		RepositoryEntity saved = new RepositoryEntity();
		saved.setRepoName("payments-api");
		BDDMockito.when(mockRepoService.update(ArgumentMatchers.eq(7L), ArgumentMatchers.any()))
				.thenReturn(saved);
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/7")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("rulesetId", "2")
				.param("team", "checkout").param("owner", "").param("labels", "pci")
				.param("criticality", "1").param("source", "bb").param("toDetail", "true"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL + "/7"));
		BDDMockito.verify(mockRepoService).update(7L, new RepositoryService.RepoEdit(2L,
				"checkout", "", "pci", 1, true));

		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/7")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("scanning", "on")
				.param("source", "bb"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL + "?source=bb"));
		BDDMockito.verify(mockRepoService).update(7L, new RepositoryService.RepoEdit(null,
				null, null, null, null, false));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void editNeedsRepositorySettingsModify() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/7")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("team", "x"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void addingAnUnknownSlugSaysSo() throws Exception {
		givenTabs(new Tab("bb", false));
		BDDMockito.when(mockRepoService.addManually(ArgumentMatchers.eq("bb"),
				ArgumentMatchers.eq("nope"), ArgumentMatchers.any()))
				.thenThrow(new IllegalArgumentException("bb has no repository named nope"));
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/add")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("source", "bb")
				.param("slug", "nope"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL + "?source=bb"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"bb has no repository named nope"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void addingAKnownSlugOpensItsPage() throws Exception {
		RepositoryEntity added = new RepositoryEntity();
		added.setRepoName("payments-api");
		BDDMockito.when(mockRepoService.addManually(ArgumentMatchers.eq("bb"),
				ArgumentMatchers.eq("payments-api"), ArgumentMatchers.any())).thenReturn(added);
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/add")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("source", "bb")
				.param("slug", "payments-api"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL + "/" + added.getId()));
	}

	@Test
	@WithMockUser(username = "alice", authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void redirectsKeepOnlyAKnownIntegrationAndStatus() throws Exception {
		givenTabs(new Tab("bb", false));
		BDDMockito.when(mockScans.requestSync("alice")).thenReturn(List.of());
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/sync")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("source", "//evil.example"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL));
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/bulk")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("action", "edit")
				.param("repoIds", "1").param("rulesetId", "4").param("source", "bb")
				.param("status", "x&next=//evil.example"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL + "?source=bb"));
		mockMvc.perform(MockMvcRequestBuilders.post("/repository/nonsense/sync")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("source", "bb"))
				.andExpect(MockMvcResultMatchers.redirectedUrl(CODE_URL));
	}

	@Test
	@WithMockUser(username = "alice", authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void bulkPauseAndDeleteOfAllMatchingResolveOnTheServerInChunks() throws Exception {
		List<Long> many = new ArrayList<>();
		for (long i = 1; i <= 501; i++) {
			many.add(i);
		}
		BDDMockito.when(mockRepoService.matchingIds(ArgumentMatchers.eq(
				CodeScanType.PULL_REQUEST), ArgumentMatchers.eq("bb"), ArgumentMatchers.any()))
				.thenReturn(many);
		BDDMockito.when(mockRepoService.setPaused(ArgumentMatchers.anyList(),
				ArgumentMatchers.eq(true))).thenAnswer(a -> ((List<?>) a.getArgument(0)).size());
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/bulk")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("action", "pause")
				.param("matching", "true").param("source", "bb").param("status", "gone"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION, "Updated 501 repositories"));
		BDDMockito.verify(mockRepoService).setPaused(many.subList(0, 500), true);
		BDDMockito.verify(mockRepoService).setPaused(many.subList(500, 501), true);

		BDDMockito.when(mockRepoService.delete(List.of(4L, 5L), "alice"))
				.thenReturn(new RepositoryService.DeleteResult(1, 1));
		mockMvc.perform(MockMvcRequestBuilders.post(PR_URL + "/bulk")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("action", "delete")
				.param("repoIds", "4", "5").param("source", "bb"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Deleted 1 repository; 1 repository being scanned left as is"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void exportIsCsvOfTheFilter() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL + "/export").param("source", "b b/x")
				.param("status", "paused"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith("text/csv"))
				.andExpect(MockMvcResultMatchers.header().string("Content-Disposition",
						"attachment; filename=\"repositories-b_b_x.csv\""));
		ArgumentCaptor<RepositoryFilter> filter = ArgumentCaptor.forClass(RepositoryFilter.class);
		BDDMockito.verify(mockCsv).export(ArgumentMatchers.eq(CodeScanType.PULL_REQUEST),
				ArgumentMatchers.eq("b b/x"), filter.capture(), ArgumentMatchers.any());
		Assertions.assertEquals(RepoStatus.PAUSED, filter.getValue().status());
	}

	@Test
	@WithMockUser(username = "alice", authorities = CorePrivilege.REPO_SETTINGS_MODIFY_NAME)
	public void importReportsTheResultAndRefusesLargeFiles() throws Exception {
		BDDMockito.when(mockCsv.importCsv(ArgumentMatchers.eq(CodeScanType.PULL_REQUEST),
				ArgumentMatchers.eq("bb"), ArgumentMatchers.any(), ArgumentMatchers.eq("alice")))
				.thenReturn(new RepositoryCsvService.ImportResult(3, 1,
						List.of("Line 3: no repository named x in this integration")));
		mockMvc.perform(MockMvcRequestBuilders.multipart(PR_URL + "/import")
				.file(new org.springframework.mock.web.MockMultipartFile("file", "r.csv",
						"text/csv", "repo,team\na,b\n".getBytes()))
				.param("source", "bb").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION, "3 updated, 1 skipped"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"Line 3: no repository named x in this integration"));

		mockMvc.perform(MockMvcRequestBuilders.multipart(PR_URL + "/import")
				.file(new org.springframework.mock.web.MockMultipartFile("file", "r.csv",
						"text/csv", new byte[(int) RepositoryCsvService.MAX_BYTES + 1]))
				.param("source", "bb").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"Choose a CSV file of at most 1 MB"));
		BDDMockito.verify(mockCsv, BDDMockito.times(1)).importCsv(ArgumentMatchers.any(),
				ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void importNeedsRepositorySettingsModify() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.multipart(PR_URL + "/import")
				.file(new org.springframework.mock.web.MockMultipartFile("file", "r.csv",
						"text/csv", "repo\na\n".getBytes()))
				.param("source", "bb").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME, CorePrivilege.ASSISTANT_SOURCE_NAME, CorePrivilege.RULE_MODIFY_NAME, CorePrivilege.REPO_SETTINGS_VIEW_NAME,
			CorePrivilege.REPO_SETTINGS_MODIFY_NAME, CorePrivilege.SCAN_SUBMIT_NAME})
	public void aRepositoryPageShowsItsFactsActionsAndScans() throws Exception {
		Row row = row("payments-api", RepoStatus.PAUSED, "Scanning is paused.");
		row.repo().setScanType(CodeScanType.PULL_REQUEST);
		row.repo().setScanningPaused(true);
		row.repo().setTeam("checkout");
		row.repo().setProjectKey("PAY");
		row.repo().setDefaultBranch("main");
		BDDMockito.when(mockInventory.row(7L)).thenReturn(java.util.Optional.of(row));
		com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity scan =
				new com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity();
		scan.setRepository(row.repo());
		scan.setBranch("release/1.0");
		scan.setStatus(com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE);
		scan.setReportKey("reports/x");
		BDDMockito.when(mockResults.page(Kind.REPOSITORY, 0, row.repo()))
				.thenReturn(new PagedResult<>(List.of(HomeActivityItem.fromRepo(scan)),
						0, 20, 1, 1));

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get(PR_URL + "/7")
				.param("view", "scans"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString(">payments-api<"),
						Matchers.containsString(">Paused<"),
						Matchers.containsString("Scanning is paused."),
						Matchers.containsString("checkout"), Matchers.containsString("PAY"),
						Matchers.containsString("aria-label=\"More actions\""),
						Matchers.containsString("Resume scanning</button>"),
						Matchers.containsString("id=\"repoEditDialog\""),
						Matchers.containsString("aria-label=\"Record a missed vulnerability\""),
						Matchers.containsString("id=\"missedCaseDialog\""),
						Matchers.containsString("No source or secrets stored"),
						Matchers.containsString("data-missed-field=\"evidenceType\""),
						Matchers.containsString("Compare the commits"),
						Matchers.containsString("data-edit-project=\"PAY\""),
						Matchers.containsString("id=\"repoScanDialog\""),
						Matchers.containsString("release/1.0"),
						Matchers.containsString("/reposcan/report/0"),
						Matchers.containsString("Delete payments-api and its repository scan history"))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void aRepositoryPageOpensOnItsPullRequestsLinkedToTheirReports() throws Exception {
		Row row = row("payments-api", RepoStatus.ACTIVE, "ok");
		row.repo().setScanType(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockInventory.row(7L)).thenReturn(java.util.Optional.of(row));
		var pr = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult();
		pr.setId(42);
		pr.setDisplayName("payments-api #12");
		pr.setApiLabel("alpha-bb");
		pr.setPrLink("https://bitbucket.org/acme/payments-api/pull-requests/12");
		pr.setResolved(true);
		pr.setStatusPresentation(com.tracelink.appsec.watchtower.core.scan.presentation.StatusPresentationModel.from(ScanStatus.DONE));
		pr.setViolations(List.of());
		BDDMockito.when(mockResults.page(Kind.PR, 1, row.repo()))
				.thenReturn(new PagedResult<>(List.of(HomeActivityItem.fromPullRequestResult(pr)),
						1, 20, 22, 2));

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get(CODE_URL + "/7")
				.param("view", "pull-requests").param("page", "1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("aria-current=\"page\""), Matchers.containsString(">Pull requests</span>"),
						Matchers.containsString("href=\"/scan/report/42\""),
						Matchers.containsString("payments-api #12"),
						Matchers.containsString(
								"href=\"https://bitbucket.org/acme/payments-api/pull-requests/12\""),
						Matchers.containsString("Resolved"),
						Matchers.containsString("Scanners"),
						Matchers.containsString("Duration"),
						Matchers.containsString("/repositories/7?view=pull-requests&amp;page=0"),
						Matchers.not(Matchers.containsString("Full repository scans only")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
		BDDMockito.verify(mockResults).page(Kind.PR, 1, row.repo());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.REPO_SETTINGS_VIEW_NAME)
	public void theHistoryNeedsScanResultsLikeTheReportsItLinksTo() throws Exception {
		Row row = row("payments-api", RepoStatus.ACTIVE, "ok");
		row.repo().setScanType(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockInventory.row(7L)).thenReturn(java.util.Optional.of(row));

		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL + "/7"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString(">payments-api<"),
						Matchers.not(Matchers.containsString("Repository history")),
						Matchers.not(Matchers.containsString("data-repository-prs")))));
		// Only the newest pull request is read, for "Last PR"; not the list.
		BDDMockito.verify(mockPullRequests, BDDMockito.never()).page(ArgumentMatchers.anyString(),
				ArgumentMatchers.anyString(), ArgumentMatchers.anyInt());
		BDDMockito.verify(mockInventory, BDDMockito.never()).scans(ArgumentMatchers.anyLong(),
				ArgumentMatchers.anyInt());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void aHistoryThatCannotBeReadLeavesTheRestOfThePage() throws Exception {
		Row row = row("payments-api", RepoStatus.ACTIVE, "ok");
		row.repo().setScanType(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockInventory.row(7L)).thenReturn(java.util.Optional.of(row));
		BDDMockito.when(mockResults.page(Kind.PR, 0, row.repo()))
				.thenThrow(new org.springframework.dao.QueryTimeoutException("slow"));

		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL + "/7"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString(">payments-api<"),
						Matchers.containsString("history is temporarily unavailable"))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void aRepositoryPageForViewersHasNoActionsAndUnknownIdsAreNotFound()
			throws Exception {
		Row row = row("legacy", RepoStatus.GONE, "Not found");
		row.repo().setScanType(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockInventory.row(8L)).thenReturn(java.util.Optional.of(row));
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL + "/8"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("No scans match this view yet."),
						Matchers.not(Matchers.containsString("repoEditDialog")),
						Matchers.not(Matchers.containsString("repoScanDialog")))));

		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL + "/9"))
				.andExpect(MockMvcResultMatchers.status().isNotFound());
		// An image repository is not shown under the code repositories' URL
		Row image = row("api", RepoStatus.ACTIVE, "ok");
		image.repo().setScanType(ImageScanType.CONTAINER);
		BDDMockito.when(mockInventory.row(10L)).thenReturn(java.util.Optional.of(image));
		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL + "/10"))
				.andExpect(MockMvcResultMatchers.status().isNotFound());
	}

	private void givenTabs(Tab... tabs) {
		BDDMockito.when(mockInventory.tabs(CodeScanType.PULL_REQUEST)).thenReturn(List.of(tabs));
	}

	private void givenRows(String apiLabel, Page<Row> page) {
		BDDMockito.when(mockInventory.rows(ArgumentMatchers.eq(CodeScanType.PULL_REQUEST),
				ArgumentMatchers.eq(apiLabel), ArgumentMatchers.any(),
				ArgumentMatchers.any(Pageable.class))).thenReturn(page);
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.REPO_SETTINGS_VIEW_NAME)
	public void lastPullRequestComesFromThePullRequestsWhenTheRepositoryRowHasNoDate() throws Exception {
		// A sync re-created the row after its pull requests were scanned: its own date is 0.
		Row row = row("wt-test", RepoStatus.ACTIVE, "ok");
		row.repo().setScanType(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockInventory.row(7L)).thenReturn(java.util.Optional.of(row));
		var latest = BDDMockito.mock(
				com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository.PullRequestSummary.class);
		BDDMockito.when(latest.getPrId()).thenReturn("58");
		BDDMockito.when(latest.isResolved()).thenReturn(false);
		BDDMockito.when(latest.getLastReviewedDate()).thenReturn(System.currentTimeMillis() - 7L * 24 * 3600 * 1000);
		BDDMockito.when(mockPullRequests.latest("alpha-bb", "wt-test")).thenReturn(java.util.Optional.of(latest));
		BDDMockito.when(mockInventory.ago(BDDMockito.anyLong())).thenReturn("7 d ago");

		mockMvc.perform(MockMvcRequestBuilders.get(PR_URL + "/7"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model().attribute("lastPr", "#58 · Open · 7 d ago"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Last PR #58 · Open · 7 d ago"),
						Matchers.not(Matchers.containsString("Last PR never")))));
	}

	private static Row row(String name, RepoStatus status, String reason) {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setApiLabel("alpha-bb");
		repo.setRepoName(name);
		repo.setEnabled(status != RepoStatus.GONE);
		return new Row(repo, status, reason, "", null);
	}

	private static Row[] rows(int count) {
		List<Row> rows = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			rows.add(row("repo-" + i, RepoStatus.ACTIVE, "ok"));
		}
		return rows.toArray(Row[]::new);
	}

	private static Page<Row> page(long total, int pageNumber, Row... rows) {
		return new PageImpl<>(List.of(rows), PageRequest.of(pageNumber, 50), total);
	}
}
