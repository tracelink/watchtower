package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import java.util.ArrayList;
import java.util.List;

import org.hamcrest.Matchers;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.IWatchtowerApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudRejectOption;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class ApiIntegrationControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	ApiIntegrationService mockApiService;

	@MockitoBean
	IntegrationHealthService mockHealth;

	@MockitoBean
	RepositoryService mockRepositories;

	@Test
	@WithMockUser(authorities = CorePrivilege.API_SETTINGS_VIEW_NAME)
	public void webhookPageKeepsWorkspaceSeparateAndRepositoryCoverageUnknown() throws Exception {
		BBCloudIntegrationEntity bb = new BBCloudIntegrationEntity();
		bb.setApiLabel("bb"); bb.setWebhookSecret("MUST-NOT-RENDER");
		BDDMockito.when(mockApiService.findByLabel("bb")).thenReturn(bb);
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/apisettings/bb/webhooks/manage"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(Matchers.containsString("MUST-NOT-RENDER"))))
				.andReturn();
		Document doc = Jsoup.parse(result.getResponse().getContentAsString());
		// The workspace hook is one slim section; it is outside the repository table, and the page
		// stays free of cards, headings-with-paragraphs and mutation controls for a viewer.
		Assertions.assertEquals(1, doc.select("[data-webhook-page] section").size());
		Assertions.assertEquals("Workspace webhook", doc.selectFirst("[data-workspace-hooks]").attr("aria-label"));
		Assertions.assertTrue(doc.selectFirst("table").closest("[data-workspace-hooks]") == null);
		Assertions.assertTrue(doc.select("[data-webhook-page] .card").isEmpty());
		Assertions.assertTrue(doc.select("[data-webhook-page] h2").isEmpty());
		Assertions.assertEquals(1, doc.select("[data-webhook-page] > p").size(), "only the hidden status line is a paragraph");
		Assertions.assertTrue(doc.select("[data-webhook-choose], [data-webhook-rotate]").isEmpty());
		HtmlAssertions.assertHtmlIntegrity(result);
		String capture = System.getProperty("watchtower.webhooks.capture");
		if (capture != null) java.nio.file.Files.writeString(java.nio.file.Path.of(capture), result.getResponse().getContentAsString());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME, CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void modifierCanOpenSeparateWorkspaceConfiguration() throws Exception {
		BBCloudIntegrationEntity bb = new BBCloudIntegrationEntity(); bb.setApiLabel("bb");
		BDDMockito.when(mockApiService.findByLabel("bb")).thenReturn(bb);
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/apisettings/bb/webhooks/manage"))
				.andExpect(MockMvcResultMatchers.status().isOk()).andReturn();
		Document doc = Jsoup.parse(result.getResponse().getContentAsString());
		Assertions.assertNotNull(doc.selectFirst("[data-workspace-hooks]"));
		Assertions.assertNotNull(doc.selectFirst("[data-webhook-choose]"));
		Assertions.assertNotNull(doc.selectFirst("[data-webhook-rotate]"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME, CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void workspaceRemovalExplainsThatRepositoryHooksKeepWorking() throws Exception {
		BBCloudIntegrationEntity bb = new BBCloudIntegrationEntity(); bb.setApiLabel("bb");
		bb.setRegisterState(RegisterState.REGISTERED); bb.setRejectOption(BBCloudRejectOption.BLOCK_PR);
		BDDMockito.when(mockApiService.findByLabel("bb")).thenReturn(bb);
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/apisettings/configure").param("apiLabel", "bb"))
				.andExpect(MockMvcResultMatchers.status().isOk()).andReturn();
		Document doc = Jsoup.parse(result.getResponse().getContentAsString());
		Assertions.assertTrue(doc.selectFirst("form[action='/apisettings/unregister']").attr("data-confirm")
				.contains("Repository hooks keep working"));
		Assertions.assertTrue(doc.selectFirst("form[action='/apisettings/unregister']").text().contains("Remove workspace webhook"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.API_SETTINGS_VIEW_NAME)
	public void webhookPageRejectsMissingAndUnsupportedIntegrations() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/apisettings/missing/webhooks/manage"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/apisettings"));
		BDDMockito.when(mockApiService.findByLabel("ecr")).thenReturn(new EcrIntegrationEntity());
		mockMvc.perform(MockMvcRequestBuilders.get("/apisettings/ecr/webhooks/manage"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/apisettings"));
	}

	///////////////////
	// Get apisettings
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME})
	public void testGetSettings() throws Exception {
		List<ApiIntegrationEntity> integrations = new ArrayList<ApiIntegrationEntity>();
		BBCloudIntegrationEntity integration = new BBCloudIntegrationEntity();
		integration.setApiLabel("primary-bitbucket");
		integration.setRejectOption(BBCloudRejectOption.BLOCK_PR);
		integrations.add(integration);
		BDDMockito.when(mockApiService.getAllSettings()).thenReturn(integrations);
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/apisettings"))
				.andExpect(MockMvcResultMatchers.model().attribute("apiTypeNames",
						Matchers.hasItems(ApiType.BITBUCKET_CLOUD.getTypeName())))
				.andExpect(MockMvcResultMatchers.model().attribute("apiSettings",
						Matchers.is(integrations)))
				.andExpect(MockMvcResultMatchers.model().attribute("hasApiSettings", true))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(
						Matchers.containsString("No API integrations configured"))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME,
			CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void healthShowsTheLastCheckAndTheDeleteDialogCountsRepositories() throws Exception {
		BBCloudIntegrationEntity failing = new BBCloudIntegrationEntity();
		failing.setApiLabel("broken-bb");
		failing.setRejectOption(BBCloudRejectOption.BLOCK_PR);
		failing.setHealth(1_800_000_000_000L, false, "401 Unauthorized");
		BBCloudIntegrationEntity unchecked = new BBCloudIntegrationEntity();
		unchecked.setApiLabel("new-bb");
		unchecked.setRejectOption(BBCloudRejectOption.BLOCK_PR);
		BDDMockito.when(mockApiService.getAllSettings()).thenReturn(List.of(failing, unchecked));
		BDDMockito.when(mockHealth.isFailing(failing)).thenReturn(true);
		BDDMockito.when(mockRepositories.countsByIntegration())
				.thenReturn(java.util.Map.of("broken-bb", 42L));

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/apisettings"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString(">Connection<"),
						Matchers.containsString(">Key rejected<"),
						Matchers.containsString("401 Unauthorized"),
						Matchers.containsString("Not checked"),
						Matchers.containsString("data-repo-count=\"42\""),
						Matchers.containsString("name=\"deleteRepositories\""))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME})
	public void registeringNeedsApiSettingsModify() throws Exception {
		for (String action : List.of("/apisettings/register", "/apisettings/unregister")) {
			mockMvc.perform(MockMvcRequestBuilders.post(action).param("apiLabel", "bb")
					.with(SecurityMockMvcRequestPostProcessors.csrf()))
					.andExpect(MockMvcResultMatchers.status().isForbidden());
		}
		BDDMockito.verify(mockApiService, BDDMockito.never()).register(BDDMockito.any());
		BDDMockito.verify(mockApiService, BDDMockito.never()).unregister(BDDMockito.any());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME})
	public void testEmptySettingsShowEmptyState() throws Exception {
		BDDMockito.when(mockApiService.getAllSettings()).thenReturn(List.of());
		mockMvc.perform(MockMvcRequestBuilders.get("/apisettings"))
				.andExpect(MockMvcResultMatchers.model().attribute("hasApiSettings", false))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("No API integrations configured")));
	}


	///////////////////
	// Create
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testCreateApi() throws Exception {
		ApiType type = ApiType.BITBUCKET_CLOUD;
		mockMvc.perform(MockMvcRequestBuilders.get("/apisettings/create").param("apiType",
				type.getTypeName()))
				.andExpect(MockMvcResultMatchers.model().attribute("apiType", type))
				.andExpect(MockMvcResultMatchers.model().attribute("template", type.getTemplate()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testCreateApiUnknown() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.get("/apisettings/create").param("apiType", "foobar"))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, "Unknown API"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/apisettings"));
	}

	///////////////////
	// Configure
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testEditApi() throws Exception {
		String label = "foo";
		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();
		entity.setRejectOption(BBCloudRejectOption.BLOCK_PR);
		BDDMockito.when(mockApiService.findByLabel(label)).thenReturn(entity);
		MvcResult result = mockMvc.perform(
				MockMvcRequestBuilders.get("/apisettings/configure").param("apiLabel", label))
				.andExpect(MockMvcResultMatchers.model().attribute("entity", entity))
				.andExpect(MockMvcResultMatchers.model().attribute("apiType", entity.getApiType()))
				.andExpect(MockMvcResultMatchers.model().attribute("template",
						entity.getApiType().getTemplate()))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME,
			CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void theIntegrationPageShowsStatesAsChipsAndSavedSecretsWithoutTheirValues()
			throws Exception {
		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();
		entity.setApiLabel("BitBucket");
		entity.setRejectOption(BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES);
		entity.setHealth(1_800_000_000_000L, true, null);
		java.util.Map<String, String> secrets = new java.util.HashMap<>(java.util.Map.of(
				"apiLabel", "BitBucket", "workspace", "ws", "user", "me@example.com",
				"auth", "TOKEN-VALUE-123", "webhookSecret", "HOOK-SECRET-456",
				"rejectOption", BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES.getName()));
		entity.configureEntityFromParameters(secrets);
		BDDMockito.when(mockApiService.findByLabel("BitBucket")).thenReturn(entity);

		MvcResult result = mockMvc.perform(
				MockMvcRequestBuilders.get("/apisettings/configure").param("apiLabel", "BitBucket"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString(">Connected<"),
						Matchers.containsString("Workspace not set up"),
						Matchers.containsString("Test connection"),
						Matchers.containsString("name=\"returnTo\" value=\"integration\""),
						Matchers.containsString("data-secret-replace"),
						Matchers.containsString("When a scan blocks a PR"),
						Matchers.containsString(">Comment and approve or request changes<"),
						Matchers.containsString("Setup guide"),
						Matchers.not(Matchers.containsString("TOKEN-VALUE-123")),
						Matchers.not(Matchers.containsString("HOOK-SECRET-456")),
						Matchers.not(Matchers.containsString("Action on rejection")))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
		Document page = Jsoup.parse(result.getResponse().getContentAsString());
		Assertions.assertNotNull(page.selectFirst(
				"input[type=radio][name=rejectOption][checked][value=\""
						+ BBCloudRejectOption.APPROVE_OR_REQUEST_CHANGES.getName() + "\"]"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME})
	public void testConnectionFromTheIntegrationPageReturnsThere() throws Exception {
		IWatchtowerApi api = BDDMockito.mock(IWatchtowerApi.class);
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.createApi()).thenReturn(api);
		BDDMockito.when(mockApiService.findByLabel("Example")).thenReturn(integrationEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/apisettings/testConnection")
				.param("apiLabel", "Example").param("returnTo", "integration")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl(
						"/apisettings/configure?apiLabel=Example"));
		// Anything else returns to the list, so the parameter can't send anyone elsewhere
		mockMvc.perform(MockMvcRequestBuilders.post("/apisettings/testConnection")
				.param("apiLabel", "Example").param("returnTo", "https://evil.example")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/apisettings"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME})
	public void aCheckThatCouldNotRunIsNotBlamedOnTheProvider() throws Exception {
		IWatchtowerApi api = BDDMockito.mock(IWatchtowerApi.class);
		BDDMockito.doThrow(new IllegalStateException("No current ServletRequestAttributes"))
				.when(api).testClientConnection();
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.createApi()).thenReturn(api);
		BDDMockito.when(mockApiService.findByLabel("Example")).thenReturn(integrationEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/apisettings/testConnection")
				.param("apiLabel", "Example").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"The check couldn't run because of a Watchtower error"));
		BDDMockito.verify(mockHealth).record(BDDMockito.eq("Example"), BDDMockito.eq(false),
				BDDMockito.startsWith(IntegrationPresentation.COULD_NOT_RUN));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testEditApiUnknown() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.get("/apisettings/configure").param("apiLabel", "foobar"))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								"Unknown API Label"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/apisettings"));
	}

	///////////////////
	// Delete apisettings
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void deletionRequiresTheIntegrationNameBeforeChangingAnything() throws Exception {
		for (String name : List.of("", "another integration")) {
			mockMvc.perform(MockMvcRequestBuilders.post("/apisettings/delete").param("apiLabel", "old-bb")
					.param("confirmName", name).param("deleteRepositories", "true")
					.with(SecurityMockMvcRequestPostProcessors.csrf()))
					.andExpect(MockMvcResultMatchers.flash().attribute(
							WatchtowerModelAndView.FAILURE_NOTIFICATION,
							"Type the integration's name to delete it."));
		}
		BDDMockito.verify(mockApiService, BDDMockito.never()).delete(BDDMockito.anyString());
		BDDMockito.verify(mockRepositories, BDDMockito.never()).delete(BDDMockito.any(), BDDMockito.any());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testDeleteSettingsBadApi() throws Exception {
		String apiLabel = "foobar";
		BDDMockito.willThrow(new ApiIntegrationException("Unknown API Label")).given(mockApiService)
				.delete(apiLabel);
		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/delete").param("apiLabel", apiLabel).param("confirmName", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.is("Unknown API Label")));
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void deletingAlsoTheRepositoriesDeletesThemAfterTheIntegration() throws Exception {
		BDDMockito.when(mockRepositories.idsOfIntegration("old-bb")).thenReturn(List.of(4L, 5L));
		BDDMockito.when(mockRepositories.delete(List.of(4L, 5L), "alice"))
				.thenReturn(new RepositoryService.DeleteResult(2, 0));
		mockMvc.perform(MockMvcRequestBuilders.post("/apisettings/delete")
				.param("apiLabel", "old-bb").param("confirmName", "old-bb").param("deleteRepositories", "true")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Deleted old-bb and 2 repositories"));
		org.mockito.InOrder order = BDDMockito.inOrder(mockApiService, mockRepositories);
		order.verify(mockApiService).delete("old-bb");
		order.verify(mockRepositories).delete(List.of(4L, 5L), "alice");
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void deletingOnlyTheIntegrationLeavesItsRepositories() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/apisettings/delete")
				.param("apiLabel", "old-bb").param("confirmName", "old-bb").with(SecurityMockMvcRequestPostProcessors.csrf()));
		BDDMockito.verify(mockApiService).delete("old-bb");
		BDDMockito.verify(mockRepositories, BDDMockito.never())
				.delete(BDDMockito.any(), BDDMockito.any());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testDeleteSettingsSuccess() throws Exception {
		String apiLabel = ApiType.BITBUCKET_CLOUD.getTypeName();
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.anyString()))
				.thenReturn(BDDMockito.mock(ApiIntegrationEntity.class));
		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/delete").param("apiLabel", apiLabel).param("confirmName", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()));

		BDDMockito.verify(mockApiService).delete(BDDMockito.anyString());
	}

	///////////////////
	// Update apisettings
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testUpdateSettingsBadApi() throws Exception {
		String apiLabel = "foobar";

		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/update").param("apiType", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.is("Unknown API")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testUpdateSettings() throws Exception {
		String apiType = ApiType.BITBUCKET_CLOUD.getTypeName();
		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/update").param("apiType", apiType)
						.param("apiLabel", "a").param("workspace", "a").param("user", "a")
						.param("auth", "a")
						.param("rejectOption", BBCloudRejectOption.BLOCK_PR.getName())
						.with(SecurityMockMvcRequestPostProcessors.csrf()));

		BDDMockito.verify(mockApiService)
				.upsertEntity(BDDMockito.any(BBCloudIntegrationEntity.class));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testUpdateSettingsKeepsConfiguredSecretsWhenInputsAreBlank() throws Exception {
		BBCloudIntegrationEntity existing = new BBCloudIntegrationEntity();
		existing.setIntegrationId(12L);
		existing.setApiLabel("configured");
		existing.setAuth("stored-auth");
		existing.setWebhookSecret("stored-webhook-secret");
		BDDMockito.when(mockApiService.findByLabel("configured")).thenReturn(existing);

		mockMvc.perform(MockMvcRequestBuilders.post("/apisettings/update")
						.param("apiType", ApiType.BITBUCKET_CLOUD.getTypeName())
						.param("apiId", "12").param("apiLabel", "configured")
						.param("workspace", "workspace").param("user", "user")
						.param("auth", "").param("webhookSecret", "")
						.param("rejectOption", BBCloudRejectOption.BLOCK_PR.getName())
						.with(SecurityMockMvcRequestPostProcessors.csrf()));

		ArgumentCaptor<ApiIntegrationEntity> captor =
				ArgumentCaptor.forClass(ApiIntegrationEntity.class);
		BDDMockito.verify(mockApiService).upsertEntity(captor.capture());
		BBCloudIntegrationEntity saved = (BBCloudIntegrationEntity) captor.getValue();
		org.junit.jupiter.api.Assertions.assertEquals("stored-auth", saved.getAuth());
		org.junit.jupiter.api.Assertions.assertEquals("stored-webhook-secret",
				saved.getWebhookSecret());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testUpdateSettingsRejectsMismatchedIntegrationIdAndLabel() throws Exception {
		BBCloudIntegrationEntity existing = new BBCloudIntegrationEntity();
		existing.setIntegrationId(99L);
		existing.setApiLabel("configured");
		BDDMockito.when(mockApiService.findByLabel("configured")).thenReturn(existing);

		mockMvc.perform(MockMvcRequestBuilders.post("/apisettings/update")
						.param("apiType", ApiType.BITBUCKET_CLOUD.getTypeName())
						.param("apiId", "12").param("apiLabel", "configured")
						.param("workspace", "workspace").param("user", "user")
						.param("auth", "replacement")
						.param("rejectOption", BBCloudRejectOption.BLOCK_PR.getName())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION, "Unknown API Label"));

		BDDMockito.verify(mockApiService, BDDMockito.never()).upsertEntity(BDDMockito.any());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testUpdateSettingsFailure() throws Exception {
		String apiLabel = ApiType.ECR.getTypeName();
		BDDMockito.doThrow(new IllegalArgumentException("Something bad")).when(mockApiService)
				.upsertEntity(BDDMockito.any());

		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/update").param("apiType", apiLabel)
						.param("apiLabel", "a").param("region", "a").param("registryId", "a")
						.param("awsAccessKey", "a").param("awsSecretKey", "a")
						.param("rejectOption", BBCloudRejectOption.BLOCK_PR.getName())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, "Something bad"));

		BDDMockito.verify(mockApiService)
				.upsertEntity(BDDMockito.any(EcrIntegrationEntity.class));
	}


	///
	// Test Connection
	///
	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME})
	public void testTestConnectionUnknown() throws Exception {
		String apiLabel = ApiType.BITBUCKET_CLOUD.getTypeName();
		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/testConnection")
						.param("apiLabel", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								"Unknown API Label"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME})
	public void testTestConnection() throws Exception {
		IWatchtowerApi api = BDDMockito.mock(IWatchtowerApi.class);
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.createApi()).thenReturn(api);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.anyString()))
				.thenReturn(integrationEntity);
		String apiLabel = "myIntegration";
		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/testConnection")
						.param("apiLabel", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Success"))
				.andExpect(MockMvcResultMatchers.flash().attribute("connectionCheckLabel", apiLabel))
				.andExpect(MockMvcResultMatchers.flash().attribute("connectionCheckTone", "success"))
				.andExpect(MockMvcResultMatchers.flash().attribute("connectionCheckTime",
						Matchers.not(Matchers.emptyString())));
		BDDMockito.verify(mockHealth).record(apiLabel, true, null);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME})
	public void testTestConnectionFailure() throws Exception {
		IWatchtowerApi api = BDDMockito.mock(IWatchtowerApi.class);
		BDDMockito.doThrow(new ApiIntegrationException("Bad connection")).when(api)
				.testClientConnection();
		ApiIntegrationEntity integrationEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(integrationEntity.createApi()).thenReturn(api);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.anyString()))
				.thenReturn(integrationEntity);

		String apiLabel = "myIntegration";
		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/testConnection")
						.param("apiLabel", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								"Bad connection"));
		BDDMockito.verify(mockHealth).record(apiLabel, false, "Bad connection");
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testRegister() throws Exception {
		String apiLabel = "myIntegration";
		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/register")
						.param("apiLabel", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Started registration"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testRegisterFailure() throws Exception {
		String apiLabel = "myIntegration";
		BDDMockito.doThrow(new ApiIntegrationException("Bad registration")).when(mockApiService)
				.register(apiLabel);

		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/register")
						.param("apiLabel", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								"Bad registration"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testUnregister() throws Exception {
		String apiLabel = "myIntegration";
		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/unregister")
						.param("apiLabel", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								"Started registration removal"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testUnregisterFailure() throws Exception {
		String apiLabel = "myIntegration";
		BDDMockito.doThrow(new ApiIntegrationException("Bad unregistration")).when(mockApiService)
				.unregister(apiLabel);

		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/unregister")
						.param("apiLabel", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								"Bad unregistration"));
	}
}
