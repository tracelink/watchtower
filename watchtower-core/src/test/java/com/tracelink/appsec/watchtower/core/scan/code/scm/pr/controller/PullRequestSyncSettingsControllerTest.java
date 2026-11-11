package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
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
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PullRequestSyncSettingsControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private PullRequestSyncSettingsService mockSettingsService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_VIEW_NAME})
	public void testGetSettings() throws Exception {
		PullRequestSyncSettingsEntity settings = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsService.getSettings()).thenReturn(settings);

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/prsettings"))
				.andExpect(MockMvcResultMatchers.model().attribute("settings", settings))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_VIEW_NAME, CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testTheSyncFrequencyIsEditedInMinutes() throws Exception {
		PullRequestSyncSettingsEntity settings = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsService.getSettings()).thenReturn(settings);

		mockMvc.perform(MockMvcRequestBuilders.get("/prsettings"))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("name=\"syncFrequencyMinutes\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("min=\"5\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("minutes")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("syncFrequencyHours"))));
	}

	@Test
	@WithMockUser
	public void testGetSettingsRejectsWithoutPrivilege() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/prsettings"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testUpdateSettings() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/prsettings/update-sync-frequency")
						.param("syncFrequencyHours", "48")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully updated Pull Request Data Sync frequency"));

		BDDMockito.verify(mockSettingsService).updateSyncFrequencyHours(48);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testUpdateAllSettingsInOneRequest() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/prsettings/update")
						.param("syncFrequencyHours", "48")
						.param("fullSourceFileThreshold", "25")
						.param("performanceWindowDays", "30")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully updated PR settings"));

		// Hours still work for callers written before minutes existed.
		BDDMockito.verify(mockSettingsService).updateSettingsMinutes(48 * 60, 25, 30);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testUpdateAllSettingsWithTheSyncFrequencyInMinutes() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/prsettings/update")
						.param("syncFrequencyMinutes", "15")
						.param("fullSourceFileThreshold", "25")
						.param("performanceWindowDays", "30")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully updated PR settings"));

		BDDMockito.verify(mockSettingsService).updateSettingsMinutes(15, 25, 30);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testUpdateAllSettingsWithoutAnySyncFrequencyIsRefused() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/prsettings/update")
						.param("fullSourceFileThreshold", "25")
						.param("performanceWindowDays", "30")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION, "Please provide a sync frequency"));

		BDDMockito.verify(mockSettingsService, BDDMockito.never()).updateSettingsMinutes(
				BDDMockito.anyInt(), BDDMockito.anyInt(), BDDMockito.anyInt());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testUpdateSettingsInvalidValue() throws Exception {
		BDDMockito.doThrow(new IllegalArgumentException(
				"Please provide a sync frequency greater than zero hours"))
				.when(mockSettingsService).updateSyncFrequencyHours(0);

		mockMvc.perform(
				MockMvcRequestBuilders.post("/prsettings/update-sync-frequency")
						.param("syncFrequencyHours", "0")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"Please provide a sync frequency greater than zero hours"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_VIEW_NAME})
	public void testUpdateSettingsRejectsViewOnlyPrivilege() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/prsettings/update-sync-frequency")
						.param("syncFrequencyHours", "48")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testUpdateFileThreshold() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/prsettings/update-file-threshold")
						.param("fullSourceFileThreshold", "10")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully updated the full-source download threshold"));

		BDDMockito.verify(mockSettingsService).updateFullSourceFileThreshold(10);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testANonNumericValueComesBackWithAMessageNotABareError() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/prsettings/update-file-threshold")
						.param("fullSourceFileThreshold", "abc")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.redirectedUrl("/prsettings"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						org.hamcrest.Matchers.containsString("whole number")));
		BDDMockito.verifyNoInteractions(mockSettingsService);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testUpdateFileThresholdInvalidValue() throws Exception {
		BDDMockito.doThrow(new IllegalArgumentException(
				"Please provide a file threshold greater than zero"))
				.when(mockSettingsService).updateFullSourceFileThreshold(0);

		mockMvc.perform(
				MockMvcRequestBuilders.post("/prsettings/update-file-threshold")
						.param("fullSourceFileThreshold", "0")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"Please provide a file threshold greater than zero"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_VIEW_NAME})
	public void testUpdateFileThresholdRejectsViewOnlyPrivilege() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/prsettings/update-file-threshold")
						.param("fullSourceFileThreshold", "10")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testUpdatePerformanceWindow() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/prsettings/update-performance-window")
						.param("performanceWindowDays", "14")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Successfully updated the PR performance window"));

		BDDMockito.verify(mockSettingsService).updatePerformanceWindowDays(14);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_VIEW_NAME, CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testTheStatusCommentSwitchIsOnByDefault() throws Exception {
		PullRequestSyncSettingsEntity settings = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSettingsService.getSettings()).thenReturn(settings);

		mockMvc.perform(MockMvcRequestBuilders.get("/prsettings"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Scan status comment")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("name=\"statusComments\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("data-switch")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("/scripts/pr-settings.js")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testTheStatusCommentSwitchIsSavedWithTheSameForm() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/prsettings/update")
				.param("syncFrequencyMinutes", "15").param("fullSourceFileThreshold", "25")
				.param("performanceWindowDays", "30").param("statusComments", "false")
				.with(SecurityMockMvcRequestPostProcessors.csrf()));

		BDDMockito.verify(mockSettingsService).updateStatusComments(false);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.PR_SETTINGS_MODIFY_NAME})
	public void testAFormWithoutTheStatusCommentChoiceLeavesItAlone() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/prsettings/update")
				.param("syncFrequencyMinutes", "15").param("fullSourceFileThreshold", "25")
				.param("performanceWindowDays", "30").with(SecurityMockMvcRequestPostProcessors.csrf()));

		BDDMockito.verify(mockSettingsService, BDDMockito.never()).updateStatusComments(BDDMockito.anyBoolean());
	}
}
