package com.tracelink.appsec.watchtower.core.alerting;

import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Assertions;
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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class AlertSettingsControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private AlertSettingsService settingsService;

	@Test
	@WithMockUser(authorities = CorePrivilege.ALERT_SETTINGS_VIEW_NAME)
	public void testPageShowsOnlyTheMaskedWebhook() throws Exception {
		BDDMockito.when(settingsService.getChannels()).thenReturn(List.of(
				new AlertSettingsService.ChannelView(1L, "appsec",
						GoogleChatWebhook.mask(GoogleChatWebhookTest.VALID), true, null, null)));
		BDDMockito.when(settingsService.getAlertTypes())
				.thenReturn(new AlertTypeRegistry().getTypes());

		mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings").param("tab", "channels"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("appsec"),
						Matchers.containsString("key=****"),
						Matchers.not(Matchers.containsString("SyExample")),
						// View-only: no add/change forms.
						Matchers.not(Matchers.containsString("/alertsettings/channels/add")))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.ALERT_SETTINGS_VIEW_NAME)
	public void testViewersCannotChangeSettings() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/alertsettings/channels/add")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("name", "appsec").param("webhookUrl", GoogleChatWebhookTest.VALID))
				.andExpect(MockMvcResultMatchers.status().isForbidden());

		BDDMockito.verify(settingsService, BDDMockito.never()).addChannel(BDDMockito.any(),
				BDDMockito.any(), BDDMockito.any());
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.ALERT_SETTINGS_VIEW_NAME,
			CorePrivilege.ALERT_SETTINGS_MODIFY_NAME})
	public void testAddChannelAsTheUser() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/alertsettings/channels/add")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("name", "appsec").param("webhookUrl", GoogleChatWebhookTest.VALID))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/alertsettings?tab=channels"));

		BDDMockito.verify(settingsService).addChannel("appsec", GoogleChatWebhookTest.VALID,
				"alice");
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.ALERT_SETTINGS_VIEW_NAME)
	public void testChannelsTabIsTheDefaultUntilAChannelExists() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings"))
				.andExpect(MockMvcResultMatchers.model().attribute("activeTab", "channels"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.ALERT_SETTINGS_VIEW_NAME)
	public void testChannelsTabStaysTheDefaultOnceAChannelExists() throws Exception {
		givenOneChannel();

		mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings"))
				.andExpect(MockMvcResultMatchers.model().attribute("activeTab", "channels"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.ALERT_SETTINGS_VIEW_NAME)
	public void testTabParameterSelectsTheTabAndUnknownTabsFallBack() throws Exception {
		givenOneChannel();
		BDDMockito.when(settingsService.history(BDDMockito.eq("all"), BDDMockito.eq("all"), BDDMockito.eq(0),
				BDDMockito.anyInt(), BDDMockito.anyMap()))
				.thenReturn(new com.tracelink.appsec.watchtower.core.mvc.PagedResult<>(java.util.List.of(), false));

		mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings").param("tab", "history"))
				.andExpect(MockMvcResultMatchers.model().attribute("activeTab", "history"));
		mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings").param("tab", "routes"))
				.andExpect(MockMvcResultMatchers.model().attribute("activeTab", "routes"));
		mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings").param("tab", "<x>"))
				.andExpect(MockMvcResultMatchers.model().attribute("activeTab", "channels"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ALERT_SETTINGS_VIEW_NAME,
			CorePrivilege.ALERT_SETTINGS_MODIFY_NAME})
	public void testChannelsComeFirstAndRowActionsAreButtons() throws Exception {
		givenOneChannel();

		String html = mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andReturn().getResponse().getContentAsString();

		// The one segmented control: an icon and a count per tab
		Document page = Jsoup.parse(html);
		Assertions.assertEquals(3, page.select("nav.wt-segmented-filter a.wt-segment .wt-count-badge").size());
		MatcherAssert.assertThat(page.select("nav.wt-segmented-filter a.wt-segment").eachText(),
				Matchers.contains("forumChannels1", "alt_routeRoutes0", "historyHistory0"));
		// Edit, Send test and Delete are matching icon buttons; Enable/Disable is in the edit
		// dialog; no card repeats the tab name; the webhook is a "Google Chat" chip.
		MatcherAssert.assertThat(html, Matchers.allOf(
				Matchers.containsString("aria-label=\"Edit channel\""),
				Matchers.containsString("data-channel-where"),
				Matchers.containsString(">Google Chat<"),
				Matchers.containsString("class=\"wt-icon-action wt-icon-action--danger\""),
				Matchers.containsString("aria-label=\"Send a test alert\""),
				Matchers.containsString("data-channel-enabled-row"),
				Matchers.not(Matchers.containsString("action=\"/alertsettings/channels/update\" method")),
				Matchers.not(Matchers.containsString("class=\"card")),
				Matchers.not(Matchers.containsString(">Edit</md-text-button>")),
				Matchers.not(Matchers.containsString(">Delete</md-text-button>"))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ALERT_SETTINGS_VIEW_NAME,
			CorePrivilege.ALERT_SETTINGS_MODIFY_NAME})
	public void testAddAndEditFormsLiveOnlyInsideDialogs() throws Exception {
		givenOneChannel();

		for (String tab : new String[] {"channels", "routes"}) {
			String html = mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings")
					.param("tab", tab))
					.andExpect(MockMvcResultMatchers.status().isOk())
					.andReturn().getResponse().getContentAsString();

			Document page = Jsoup.parse(html);
			Assertions.assertNotNull(page.selectFirst("md-dialog#routeDialog form#routeForm"));
			Assertions.assertNotNull(page.selectFirst("md-dialog#channelDialog form#channelForm"));
			Assertions.assertNotNull(page.selectFirst("md-dialog#confirmDeleteDialog"));
			Assertions.assertNotNull(page.selectFirst(
					"[data-wt-dialog-target=#" + (tab.equals("routes") ? "route" : "channel")
							+ "Dialog]"));
			// An edit form has fields to fill in; the Enable/Disable toggle posts only hidden ones.
			for (Element form : page.select(
					"form[action~=/alertsettings/(routes|channels)/(add|update)]")) {
				boolean hasFields = !form.select(
						"input:not([type=hidden]), md-outlined-text-field, md-outlined-select")
						.isEmpty();
				Assertions.assertFalse(hasFields && form.parents().select("md-dialog").isEmpty(),
						"add/edit form outside a dialog: " + form.attr("action"));
			}
		}
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.ALERT_SETTINGS_VIEW_NAME,
			CorePrivilege.ALERT_SETTINGS_MODIFY_NAME})
	public void testUpdateRouteSavesTheEditAndReturnsToRoutes() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/alertsettings/routes/update")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("id", "5")
				.param("alertType", AlertTypeRegistry.SCANNER_FAILURE).param("channelId", "1")
				.param("minPriority", "").param("aggregation", "PER_SCAN")
				.param("repoInclude", "payments-*").param("dedupeWindowHours", "48"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/alertsettings?tab=routes"))
				.andExpect(MockMvcResultMatchers.flash().attributeExists("success"));

		BDDMockito.verify(settingsService).updateRoute(5L, new AlertSettingsService.RouteRequest(
				AlertTypeRegistry.SCANNER_FAILURE, 1L, null, null, "payments-*", null,
				AlertAggregation.PER_SCAN, 48), "alice");
	}

	private void givenOneChannel() {
		BDDMockito.when(settingsService.getChannels()).thenReturn(List.of(
				new AlertSettingsService.ChannelView(1L, "appsec",
						GoogleChatWebhook.mask(GoogleChatWebhookTest.VALID), true, null, null)));
		BDDMockito.when(settingsService.getAlertTypes())
				.thenReturn(new AlertTypeRegistry().getTypes());
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.ALERT_SETTINGS_VIEW_NAME,
			CorePrivilege.ALERT_SETTINGS_MODIFY_NAME})
	public void testAddRouteParsesItsOptions() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/alertsettings/routes/add")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("alertType", AlertTypeRegistry.SCANNER_FAILURE).param("channelId", "1")
				.param("minPriority", "HIGH").param("aggregation", "PER_FINDING")
				.param("dedupeWindowHours", "24"))
				.andExpect(MockMvcResultMatchers.flash().attributeExists("success"));

		BDDMockito.verify(settingsService).addRoute(new AlertSettingsService.RouteRequest(
				AlertTypeRegistry.SCANNER_FAILURE, 1L, RulePriority.HIGH, null, null, null,
				AlertAggregation.PER_FINDING, 24), "alice");
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.ALERT_SETTINGS_VIEW_NAME,
			CorePrivilege.ALERT_SETTINGS_MODIFY_NAME})
	public void testARouteWithNoRepositoryFilterIsSavedWithAWarning() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/alertsettings/routes/add")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("alertType", AlertTypeRegistry.SCANNER_FAILURE).param("channelId", "1"))
				.andExpect(MockMvcResultMatchers.flash().attribute("success",
						Matchers.allOf(Matchers.startsWith("Added the route."),
								Matchers.containsString("no integration or repository filter"))));
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.ALERT_SETTINGS_VIEW_NAME,
			CorePrivilege.ALERT_SETTINGS_MODIFY_NAME})
	public void testARouteWithARepositoryFilterIsSavedWithoutAWarning() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/alertsettings/routes/add")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("alertType", AlertTypeRegistry.SCANNER_FAILURE).param("channelId", "1")
				.param("repoInclude", "payments-*"))
				.andExpect(MockMvcResultMatchers.flash().attribute("success", "Added the route."));
	}

	@Test
	@WithMockUser(username = "alice", authorities = {CorePrivilege.ALERT_SETTINGS_VIEW_NAME,
			CorePrivilege.ALERT_SETTINGS_MODIFY_NAME})
	public void testAnUnknownGroupingIsRefusedWithoutEchoingIt() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/alertsettings/routes/add")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("alertType", AlertTypeRegistry.SCANNER_FAILURE).param("channelId", "1")
				.param("aggregation", "<script>"))
				.andExpect(MockMvcResultMatchers.flash().attribute("failure",
						Matchers.not(Matchers.containsString("<"))));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.ALERT_SETTINGS_VIEW_NAME)
	public void testHistoryShowsSourceRepositoryTimesAndRejectsUnknownFilters() throws Exception {
		givenOneChannel();
		var row = new AlertHistoryRow(7, 1_700_000_000_000L, 1_700_000_005_000L, "Secret detected", "payments-api",
				"Security space", "Sent", 0, null, "*Secret detected*\nRepository: payments-api", "/scan/report/42");
		BDDMockito.when(settingsService.history(BDDMockito.eq("SENT"), BDDMockito.eq("all"), BDDMockito.eq(0),
				BDDMockito.anyInt(), BDDMockito.anyMap()))
				.thenReturn(new com.tracelink.appsec.watchtower.core.mvc.PagedResult<>(java.util.List.of(row), 0, 25, 1, 1));
		BDDMockito.when(settingsService.history(BDDMockito.eq("bogus"), BDDMockito.anyString(), BDDMockito.anyInt(),
				BDDMockito.anyInt(), BDDMockito.anyMap())).thenThrow(new IllegalArgumentException("Choose a known status"));

		mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings").param("tab", "history").param("status", "SENT"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(org.hamcrest.Matchers.allOf(
						org.hamcrest.Matchers.containsString("payments-api"),
						org.hamcrest.Matchers.containsString("href=\"/scan/report/42\""),
						// Delivery is one chip with how long it took; the retries column only
						// shows when a send on the page failed
						org.hamcrest.Matchers.containsString("Sent · 5 s"),
						org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("Failed attempts")),
						org.hamcrest.Matchers.containsString("1700000005000"))));
		mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings").param("tab", "history").param("status", "bogus"))
				.andExpect(MockMvcResultMatchers.status().isBadRequest());
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.ALERT_SETTINGS_VIEW_NAME)
	public void routesReadAsChipsWithTheRepeatWindowInDays() throws Exception {
		givenOneChannel();
		var channel = new com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity();
		channel.setName("Personal space");
		var route = new com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity();
		route.setAlertType("SECRET_DETECTED");
		route.setChannel(channel);
		route.setEnabled(true);
		route.setAggregation(AlertAggregation.PER_SCAN);
		route.setDedupeWindowHours(720);
		BDDMockito.when(settingsService.getRoutes()).thenReturn(List.of(route));

		mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings").param("tab", "routes"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString(">Secret detected<"),
						Matchers.containsString(">Personal space<"),
						Matchers.containsString("No repeats for 30 days"),
						Matchers.containsString(">1 per scan<"),
						Matchers.containsString(">All alerts<"),
						Matchers.not(Matchers.containsString("no repeats for 720")))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ALERT_SETTINGS_VIEW_NAME,
			CorePrivilege.ALERT_SETTINGS_MODIFY_NAME})
	public void populatedRoutesRenderTheirAdminActions() throws Exception {
		givenOneChannel();
		var channel = new com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity();
		org.springframework.test.util.ReflectionTestUtils.setField(channel, "id", 1L);
		channel.setName("Personal space");
		var route = new com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity();
		org.springframework.test.util.ReflectionTestUtils.setField(route, "id", 7L);
		route.setAlertType(AlertTypeRegistry.SCANNER_FAILURE);
		route.setChannel(channel);
		route.setEnabled(true);
		route.setAggregation(AlertAggregation.PER_SCAN);
		route.setMinPriority(RulePriority.HIGH);
		route.setDedupeWindowHours(720);
		BDDMockito.when(settingsService.getRoutes()).thenReturn(List.of(route));

		String html = mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings").param("tab", "routes"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andReturn().getResponse().getContentAsString();
		Document page = Jsoup.parse(html);
		Assertions.assertEquals("7", page.selectFirst("[data-route-edit]").attr("data-id"));
		Assertions.assertEquals("HIGH", page.selectFirst("[data-route-edit]").attr("data-min-priority"));
		Assertions.assertTrue(page.text().contains("High and above"));
		// Pause and Delete are rarely used, so they sit behind the more-actions menu, not next to Edit
		Assertions.assertNotNull(page.selectFirst("details.wt-row-menu > summary[aria-label='More route actions']"));
		Assertions.assertNotNull(page.selectFirst("details.wt-row-menu button.wt-menu-item:contains(Pause route)"));
		Assertions.assertNotNull(page.selectFirst(
				"details.wt-row-menu button.wt-menu-item--danger[data-wt-dialog-target=#confirmDeleteDialog]:contains(Delete route)"));
		Assertions.assertNull(page.selectFirst("td > .wt-table-actions > button[aria-label='Delete route']"));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.ALERT_SETTINGS_VIEW_NAME)
	public void failedSendsShowAsRetriesOnlyWhenThereAreAny() throws Exception {
		givenOneChannel();
		var retried = new AlertHistoryRow(8, 1_700_000_000_000L, 1_700_000_120_000L, "Secret detected",
				"payments-api", "Security space", "Sent", 2, "503", "*Secret detected*", null);
		BDDMockito.when(settingsService.history(BDDMockito.eq("all"), BDDMockito.eq("all"), BDDMockito.eq(0),
				BDDMockito.anyInt(), BDDMockito.anyMap()))
				.thenReturn(new com.tracelink.appsec.watchtower.core.mvc.PagedResult<>(List.of(retried), 0, 25, 1, 1));

		mockMvc.perform(MockMvcRequestBuilders.get("/alertsettings").param("tab", "history"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Failed attempts"),
						Matchers.containsString(">2 retries<"),
						Matchers.containsString("Sent · 2 min"),
						Matchers.containsString("Status: All"),
						Matchers.containsString("Alert: All"))));
	}

	@Test
	public void testHistoryRowReadsRepositoryAndLinkFromTheSentMessage() {
		var log = new com.tracelink.appsec.watchtower.core.alerting.entity.AlertLogEntity();
		log.setAlertType("SECRET_DETECTED");
		log.setChannelId(3);
		log.setStatus(AlertStatus.FAILED);
		log.setAttempts(5);
		log.setPayload("*Secret detected*\nRepository: payments-api\n• token in a.env\n<https://wt.example/scan/report/9|Open in Watchtower>");
		var row = AlertHistoryRow.from(log, java.util.Map.of());
		org.junit.jupiter.api.Assertions.assertEquals("payments-api", row.repository());
		org.junit.jupiter.api.Assertions.assertEquals("https://wt.example/scan/report/9", row.sourceLink());
		org.junit.jupiter.api.Assertions.assertEquals("Deleted channel", row.channel());
		org.junit.jupiter.api.Assertions.assertEquals("Secret detected", row.type());
		org.junit.jupiter.api.Assertions.assertEquals("Failed", row.status());
		log.setPayload("<javascript:alert(1)|Open in Watchtower>");
		org.junit.jupiter.api.Assertions.assertNull(AlertHistoryRow.from(log, java.util.Map.of()).sourceLink(),
				"only http(s) or app-relative links are rendered");
	}
}
