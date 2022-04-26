package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import java.util.ArrayList;
import java.util.List;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class ApiIntegrationControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	ApiIntegrationService mockApiService;

	///////////////////
	// Get apisettings
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_VIEW_NAME})
	public void testGetSettings() throws Exception {
		List<ApiIntegrationEntity> integrations = new ArrayList<ApiIntegrationEntity>();
		BDDMockito.when(mockApiService.getAllSettings()).thenReturn(integrations);
		mockMvc.perform(MockMvcRequestBuilders.get("/apisettings"))
				.andExpect(MockMvcResultMatchers.model().attribute("apiTypeNames",
						Matchers.hasItems(ApiType.BITBUCKET_CLOUD.getTypeName())))
				.andExpect(MockMvcResultMatchers.model().attribute("apiSettings",
						Matchers.is(integrations)));
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
		ApiIntegrationEntity entity = new BBCloudIntegrationEntity();
		BDDMockito.when(mockApiService.findByLabel(label)).thenReturn(entity);
		mockMvc.perform(
				MockMvcRequestBuilders.get("/apisettings/configure").param("apiLabel", label))
				.andExpect(MockMvcResultMatchers.model().attribute("entity", entity))
				.andExpect(MockMvcResultMatchers.model().attribute("apiType", entity.getApiType()))
				.andExpect(MockMvcResultMatchers.model().attribute("template",
						entity.getApiType().getTemplate()));
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
	public void testDeleteSettingsBadApi() throws Exception {
		String apiLabel = "foobar";

		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/delete").param("apiLabel", apiLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.is("Unknown API Label")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.API_SETTINGS_MODIFY_NAME})
	public void testDeleteSettingsSuccess() throws Exception {
		String apiLabel = ApiType.BITBUCKET_CLOUD.getTypeName();
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.anyString()))
				.thenReturn(BDDMockito.mock(ApiIntegrationEntity.class));
		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/delete").param("apiLabel", apiLabel)
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
		String apiLabel = ApiType.BITBUCKET_CLOUD.getTypeName();
		mockMvc.perform(
				MockMvcRequestBuilders.post("/apisettings/update").param("apiType", apiLabel)
						.param("apiLabel", "a").param("workspace", "a").param("user", "a")
						.param("auth", "a").with(SecurityMockMvcRequestPostProcessors.csrf()));

		BDDMockito.verify(mockApiService)
				.upsertEntity(BDDMockito.any(BBCloudIntegrationEntity.class));
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
}
