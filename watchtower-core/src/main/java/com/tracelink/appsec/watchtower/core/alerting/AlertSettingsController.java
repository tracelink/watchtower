package com.tracelink.appsec.watchtower.core.alerting;

import java.security.Principal;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;

/**
 * Configuration - Alert Settings: routes, channels and recent alerts, one tab each. Adding and
 * editing happen in dialogs; every action returns to the tab it was made on.
 *
 * @author Watchtower
 */
@Controller
@RequestMapping("/alertsettings")
@PreAuthorize("hasAuthority('" + CorePrivilege.ALERT_SETTINGS_VIEW_NAME + "')")
public class AlertSettingsController {

	static final String TAB_ROUTES = "routes";
	static final String TAB_CHANNELS = "channels";
	static final String TAB_HISTORY = "history";
	private static final Set<String> TABS = Set.of(TAB_ROUTES, TAB_CHANNELS, TAB_HISTORY);
	private static final int HISTORY_PAGE_SIZE = 25;

	private static final String MODIFY =
			"hasAuthority('" + CorePrivilege.ALERT_SETTINGS_MODIFY_NAME + "')";

	private final AlertSettingsService settingsService;
	private final ApiIntegrationService integrations;

	public AlertSettingsController(@Autowired AlertSettingsService settingsService,
			@Autowired ApiIntegrationService integrations) {
		this.settingsService = settingsService;
		this.integrations = integrations;
	}

	@GetMapping("")
	public WatchtowerModelAndView getSettings(@RequestParam(required = false) String tab,
			@RequestParam(defaultValue = "all") String status, @RequestParam(defaultValue = "all") String type,
			@RequestParam(defaultValue = "0") int page) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/alertsettings");
		var channels = settingsService.getChannels();
		// Channels are where alerts end up, so the page always opens on them.
		mav.addObject("activeTab", tab != null && TABS.contains(tab) ? tab : TAB_CHANNELS);
		mav.addObject("channels", channels);
		var channelNames = channels.stream().collect(Collectors.toMap(
				AlertSettingsService.ChannelView::id, AlertSettingsService.ChannelView::name));
		mav.addObject("channelNames", channelNames);
		mav.addObject("routes", settingsService.getRoutes());
		mav.addObject("historyCount", settingsService.historyCount());
		mav.addObject("alertTypes", settingsService.getAlertTypes());
		mav.addObject("priorities", RulePriority.values());
		mav.addObject("aggregations", AlertAggregation.values());
		// The route dialog's "Integration" choice: All, or one of the configured integrations.
		mav.addObject("integrationLabels", integrations.getAllSettings().stream()
				.map(ApiIntegrationEntity::getApiLabel).sorted(String.CASE_INSENSITIVE_ORDER).toList());
		if (TAB_HISTORY.equals(tab)) {
			try {
				mav.addObject("history", settingsService.history(status, type, page, HISTORY_PAGE_SIZE, channelNames));
			} catch (IllegalArgumentException invalid) {
				throw new org.springframework.web.server.ResponseStatusException(
						org.springframework.http.HttpStatus.BAD_REQUEST, invalid.getMessage());
			}
			mav.addObject("historyStatus", status);
			mav.addObject("historyType", type);
			mav.addObject("historyStatuses", AlertStatus.values());
			mav.addObject("historyUrl", org.springframework.web.util.UriComponentsBuilder.fromPath("/alertsettings")
					.queryParam("tab", TAB_HISTORY).queryParam("status", "{status}").queryParam("type", "{type}")
					.encode().buildAndExpand(status, type).toUriString());
		}
		mav.addObject("credentialsEncrypted", settingsService.isCredentialEncryptionActive());
		mav.addScriptReference("/scripts/alert-settings.js");
		return mav;
	}

	@PostMapping("/channels/add")
	@PreAuthorize(MODIFY)
	public String addChannel(@RequestParam String name, @RequestParam String webhookUrl,
			Principal principal, RedirectAttributes attributes) {
		return run(attributes, TAB_CHANNELS, "Added the channel.",
				() -> settingsService.addChannel(name, webhookUrl, principal.getName()));
	}

	@PostMapping("/channels/update")
	@PreAuthorize(MODIFY)
	public String updateChannel(@RequestParam long id, @RequestParam String name,
			@RequestParam(required = false) String webhookUrl,
			@RequestParam(defaultValue = "false") boolean enabled, Principal principal,
			RedirectAttributes attributes) {
		return run(attributes, TAB_CHANNELS, "Updated the channel.",
				() -> settingsService.updateChannel(id, name, webhookUrl, enabled,
						principal.getName()));
	}

	@PostMapping("/channels/delete")
	@PreAuthorize(MODIFY)
	public String deleteChannel(@RequestParam long id, Principal principal,
			RedirectAttributes attributes) {
		return run(attributes, TAB_CHANNELS, "Deleted the channel.",
				() -> settingsService.deleteChannel(id, principal.getName()));
	}

	@PostMapping("/channels/test")
	@PreAuthorize(MODIFY)
	public String testChannel(@RequestParam long id, Principal principal,
			RedirectAttributes attributes) {
		try {
			String outcome = settingsService.testChannel(id, principal.getName());
			attributes.addFlashAttribute(outcome.startsWith("Sent")
					? WatchtowerModelAndView.SUCCESS_NOTIFICATION
					: WatchtowerModelAndView.FAILURE_NOTIFICATION, "Test alert: " + outcome);
		} catch (IllegalArgumentException e) {
			attributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return redirect(TAB_CHANNELS);
	}

	@PostMapping("/routes/add")
	@PreAuthorize(MODIFY)
	public String addRoute(@RequestParam String alertType, @RequestParam long channelId,
			@RequestParam(required = false) String minPriority,
			@RequestParam(required = false) String apiLabelFilter,
			@RequestParam(required = false) String repoInclude,
			@RequestParam(required = false) String repoExclude,
			@RequestParam(required = false) String aggregation,
			@RequestParam(defaultValue = "720") int dedupeWindowHours, Principal principal,
			RedirectAttributes attributes) {
		return run(attributes, TAB_ROUTES,
				"Added the route." + unfilteredWarning(apiLabelFilter, repoInclude, repoExclude),
				() -> settingsService.addRoute(
				routeRequest(alertType, channelId, minPriority, apiLabelFilter, repoInclude,
						repoExclude, aggregation, dedupeWindowHours),
				principal.getName()));
	}

	@PostMapping("/routes/update")
	@PreAuthorize(MODIFY)
	public String updateRoute(@RequestParam long id, @RequestParam String alertType,
			@RequestParam long channelId,
			@RequestParam(required = false) String minPriority,
			@RequestParam(required = false) String apiLabelFilter,
			@RequestParam(required = false) String repoInclude,
			@RequestParam(required = false) String repoExclude,
			@RequestParam(required = false) String aggregation,
			@RequestParam(defaultValue = "720") int dedupeWindowHours, Principal principal,
			RedirectAttributes attributes) {
		return run(attributes, TAB_ROUTES,
				"Updated the route." + unfilteredWarning(apiLabelFilter, repoInclude, repoExclude),
				() -> settingsService.updateRoute(id,
						routeRequest(alertType, channelId, minPriority, apiLabelFilter,
								repoInclude, repoExclude, aggregation, dedupeWindowHours),
						principal.getName()));
	}

	@PostMapping("/routes/toggle")
	@PreAuthorize(MODIFY)
	public String toggleRoute(@RequestParam long id, @RequestParam boolean enabled,
			Principal principal, RedirectAttributes attributes) {
		return run(attributes, TAB_ROUTES, enabled ? "Enabled the route." : "Disabled the route.",
				() -> settingsService.setRouteEnabled(id, enabled, principal.getName()));
	}

	@PostMapping("/routes/delete")
	@PreAuthorize(MODIFY)
	public String deleteRoute(@RequestParam long id, Principal principal,
			RedirectAttributes attributes) {
		return run(attributes, TAB_ROUTES, "Deleted the route.",
				() -> settingsService.deleteRoute(id, principal.getName()));
	}

	/**
	 * A route with no integration or repository filter sends every matching alert of every
	 * repository, which surprised a tester when dummy-secret scans reached a real channel. Said
	 * after the save, since a route like that is sometimes exactly what is wanted.
	 */
	static String unfilteredWarning(String apiLabelFilter, String repoInclude, String repoExclude) {
		if (StringUtils.isNotBlank(apiLabelFilter) || StringUtils.isNotBlank(repoInclude)
				|| StringUtils.isNotBlank(repoExclude)) {
			return "";
		}
		return " Warning: it has no integration or repository filter, so these alerts are sent"
				+ " for every repository, including test ones. Add a filter to narrow it.";
	}

	private static AlertSettingsService.RouteRequest routeRequest(String alertType,
			long channelId, String minPriority, String apiLabelFilter, String repoInclude,
			String repoExclude, String aggregation, int dedupeWindowHours) {
		return new AlertSettingsService.RouteRequest(alertType, channelId,
				parseOptional(minPriority, RulePriority.values(), "priority"),
				apiLabelFilter, repoInclude, repoExclude,
				parseOptional(aggregation, AlertAggregation.values(), "grouping"),
				dedupeWindowHours);
	}

	private static String redirect(String tab) {
		return "redirect:/alertsettings?tab=" + tab;
	}

	private static String run(RedirectAttributes attributes, String tab, String success,
			Runnable action) {
		try {
			action.run();
			attributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION, success);
		} catch (IllegalArgumentException e) {
			attributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		} catch (org.springframework.dao.OptimisticLockingFailureException e) {
			attributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"That route was changed by someone else. Reload and try again.");
		}
		return redirect(tab);
	}

	/** Parses an optional enum field without echoing an unknown value. */
	private static <E extends Enum<E>> E parseOptional(String value, E[] values, String field) {
		if (StringUtils.isBlank(value)) {
			return null;
		}
		Map<String, E> byName = Arrays.stream(values)
				.collect(Collectors.toMap(Enum::name, Function.identity()));
		E parsed = byName.get(value.trim());
		if (parsed == null) {
			throw new IllegalArgumentException("Choose a valid " + field + ".");
		}
		return parsed;
	}
}
