package com.tracelink.appsec.module.betterleaks.allowlist;

import java.security.Principal;
import java.time.LocalDate;
import java.util.List;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageImpl;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryFilter;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class BetterleaksAllowlistControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private BetterleaksAllowlistController controller;

	@MockitoBean
	private BetterleaksAllowlistService allowlistService;

	@MockitoBean
	private RepositoryService repositoryService;

	private Principal alice;

	@BeforeEach
	public void setup() {
		alice = BDDMockito.mock(Principal.class);
		BDDMockito.when(alice.getName()).thenReturn("alice");
		BDDMockito.when(allowlistService.getKnownRuleIds()).thenReturn(Set.of("github-pat"));
	}

	private static String flash(RedirectAttributes attributes, String key) {
		Object value = attributes.getFlashAttributes().get(key);
		return value == null ? null : value.toString();
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)
	public void testPageListsEntriesAndRules() throws Exception {
		BetterleaksAllowlistEntryEntity entry = new BetterleaksAllowlistEntryEntity();
		entry.setScope(BetterleaksAllowlistScope.GLOBAL);
		entry.setPathGlob("src/test/**");
		entry.setReason("fixtures");
		entry.setCreatedBy("alice");
		BDDMockito.when(allowlistService.getEntries()).thenReturn(List.of(entry));

		String html = mockMvc.perform(MockMvcRequestBuilders.get("/betterleaks/allowlist"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model().attribute("entries", List.of(entry)))
				.andReturn().getResponse().getContentAsString();

		MatcherAssert.assertThat(html, Matchers.allOf(Matchers.containsString("src/test/**"),
				Matchers.containsString("github-pat")));
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)
	public void anEmptyAllowlistIsOnePictureAndTheAddDialogHasScopeButtons() throws Exception {
		BDDMockito.when(allowlistService.getEntries()).thenReturn(List.of());

		String html = mockMvc.perform(MockMvcRequestBuilders.get("/betterleaks/allowlist"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andReturn().getResponse().getContentAsString();

		MatcherAssert.assertThat(html, Matchers.allOf(
				Matchers.containsString("data-allowlist-empty"),
				Matchers.not(Matchers.containsString("<table")),
				Matchers.not(Matchers.containsString("No allowlist entries.<")),
				Matchers.containsString("type=\"radio\" name=\"scope\""),
				Matchers.containsString("data-repo-suggest-url=\"/betterleaks/allowlist/repositories\""),
				Matchers.containsString("data-allowlist-warning"),
				Matchers.containsString("data-wt-dialog-close")));
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)
	public void theRepositoryFieldSuggestsKnownRepositoriesOfAnyIntegration() throws Exception {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRepoName("wt-test");
		repo.setApiLabel("BitBucket");
		repo.setEnabled(true);
		BDDMockito.when(repositoryService.list(BDDMockito.eq(CodeScanType.PULL_REQUEST),
				BDDMockito.isNull(), BDDMockito.any(), BDDMockito.any()))
				.thenReturn(new PageImpl<>(List.of(repo)));

		mockMvc.perform(MockMvcRequestBuilders.get("/betterleaks/allowlist/repositories")
				.param("q", "wt"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.jsonPath("$[0].name").value("wt-test"))
				.andExpect(MockMvcResultMatchers.jsonPath("$[0].project").value("BitBucket"))
				.andExpect(MockMvcResultMatchers.jsonPath("$[0].status").value("Active"));
		ArgumentCaptor<RepositoryFilter> filter = ArgumentCaptor.forClass(RepositoryFilter.class);
		BDDMockito.verify(repositoryService).list(BDDMockito.eq(CodeScanType.PULL_REQUEST),
				BDDMockito.isNull(), filter.capture(), BDDMockito.any());
		Assertions.assertEquals("wt", filter.getValue().text());
	}

	@Test
	@WithMockUser(authorities = "Some Other Privilege")
	public void repositorySuggestionsNeedTheAllowlistPrivilege() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/betterleaks/allowlist/repositories"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)
	public void testPagePrefillsAnEntryFromAFinding() throws Exception {
		String html = mockMvc.perform(MockMvcRequestBuilders.get("/betterleaks/allowlist")
				.param("repo", "payments").param("path", "src/config/app.yml")
				.param("rule", "github-pat"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andReturn().getResponse().getContentAsString();

		MatcherAssert.assertThat(html, Matchers.allOf(
				Matchers.containsString("data-allowlist-prefill"),
				Matchers.containsString("value=\"payments\""),
				Matchers.containsString("value=\"src/config/app.yml\""),
				Matchers.matchesPattern("(?s).*value=\"github-pat\"\\s+selected.*")));
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)
	public void testPrefillOfAnUnlistedRuleStillSelectsIt() throws Exception {
		String html = mockMvc.perform(MockMvcRequestBuilders.get("/betterleaks/allowlist")
				.param("repo", "payments").param("path", "a.yml").param("rule", "custom-rule"))
				.andReturn().getResponse().getContentAsString();

		MatcherAssert.assertThat(html,
				Matchers.matchesPattern("(?s).*value=\"custom-rule\"\\s+selected.*"));
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)
	public void testPageWithoutPrefillHasNoNote() throws Exception {
		String html = mockMvc.perform(MockMvcRequestBuilders.get("/betterleaks/allowlist"))
				.andReturn().getResponse().getContentAsString();

		MatcherAssert.assertThat(html,
				Matchers.not(Matchers.containsString("data-allowlist-prefill")));
	}

	@Test
	@WithMockUser(authorities = "Some Other Privilege")
	public void testPageNeedsTheAllowlistPrivilege() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/betterleaks/allowlist"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)
	public void testAddPassesTheFormAndAuthorToTheService() {
		RedirectAttributes attributes = new RedirectAttributesModelMap();

		String view = controller.addEntry("REPO", "payments", "src/test/**", "github-pat",
				"fixture tokens", "2026-10-01", alice, attributes);

		ArgumentCaptor<BetterleaksAllowlistRequest> request =
				ArgumentCaptor.forClass(BetterleaksAllowlistRequest.class);
		BDDMockito.verify(allowlistService).addEntry(request.capture(), BDDMockito.eq("alice"));
		Assertions.assertEquals(new BetterleaksAllowlistRequest(BetterleaksAllowlistScope.REPO,
				"payments", "src/test/**", "github-pat", "fixture tokens",
				LocalDate.of(2026, 10, 1)), request.getValue());
		Assertions.assertEquals(BetterleaksAllowlistController.REDIRECT, view);
		MatcherAssert.assertThat(flash(attributes, WatchtowerModelAndView.SUCCESS_NOTIFICATION),
				Matchers.containsString("Added"));
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)
	public void testAddShowsTheValidationMessage() {
		BDDMockito.when(allowlistService.addEntry(BDDMockito.any(), BDDMockito.any()))
				.thenThrow(new IllegalArgumentException("A reason is required."));
		RedirectAttributes attributes = new RedirectAttributesModelMap();

		controller.addEntry("GLOBAL", null, "src/**", null, "", null, alice, attributes);

		Assertions.assertEquals("A reason is required.",
				flash(attributes, WatchtowerModelAndView.FAILURE_NOTIFICATION));
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)
	public void testUnparseableScopeOrDateIsReportedWithoutEchoingIt() {
		RedirectAttributes attributes = new RedirectAttributesModelMap();

		controller.addEntry("<script>", null, "src/**", null, "why", null, alice, attributes);
		controller.addEntry("GLOBAL", null, "src/**", null, "why", "<b>soon</b>", alice,
				attributes);

		BDDMockito.verify(allowlistService, BDDMockito.never()).addEntry(BDDMockito.any(),
				BDDMockito.any());
		MatcherAssert.assertThat(flash(attributes, WatchtowerModelAndView.FAILURE_NOTIFICATION),
				Matchers.not(Matchers.containsString("<")));
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)
	public void testDeleteRemovesTheEntryAsTheUser() {
		RedirectAttributes attributes = new RedirectAttributesModelMap();

		controller.deleteEntry(5L, alice, attributes);

		BDDMockito.verify(allowlistService).deleteEntry(5L, "alice");
		MatcherAssert.assertThat(flash(attributes, WatchtowerModelAndView.SUCCESS_NOTIFICATION),
				Matchers.containsString("Deleted"));
	}
}
