package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

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
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService;

/**
 * Controller for viewing and editing the admin-configurable PR settings: the {@link
 * com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSynchronizer} sync
 * frequency (IMPROVEMENT_PLAN.md item 5.2) and the changed-file count threshold above which a
 * PR scan downloads the full repository instead of fetching each changed file individually.
 */
@Controller
@RequestMapping("/prsettings")
@PreAuthorize("hasAuthority('" + CorePrivilege.PR_SETTINGS_VIEW_NAME + "')")
public class PullRequestSyncSettingsController {

	private final PullRequestSyncSettingsService settingsService;

	public PullRequestSyncSettingsController(
			@Autowired PullRequestSyncSettingsService settingsService) {
		this.settingsService = settingsService;
	}

	@GetMapping("")
	public WatchtowerModelAndView getSettings() {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/prsettings")
				.addScriptReference("/scripts/pr-settings.js");
		mav.addObject("settings", settingsService.getSettings());
		return mav;
	}

	@PostMapping("/update")
	@PreAuthorize("hasAuthority('" + CorePrivilege.PR_SETTINGS_MODIFY_NAME + "')")
	public String updateSettings(@RequestParam(required = false) String syncFrequencyMinutes,
			@RequestParam(required = false) String syncFrequencyHours,
			@RequestParam String fullSourceFileThreshold, @RequestParam String performanceWindowDays,
			@RequestParam(required = false) Boolean statusComments,
			RedirectAttributes redirectAttributes) {
		try {
			// Minutes is the setting; hours is accepted for callers written before minutes existed.
			if (StringUtils.isBlank(syncFrequencyMinutes) && StringUtils.isBlank(syncFrequencyHours)) {
				throw new IllegalArgumentException("Please provide a sync frequency");
			}
			int minutes = StringUtils.isNotBlank(syncFrequencyMinutes)
					? wholeNumber(syncFrequencyMinutes, "sync frequency")
					: wholeNumber(syncFrequencyHours, "sync frequency") * 60;
			settingsService.updateSettingsMinutes(minutes,
					wholeNumber(fullSourceFileThreshold, "file threshold"),
					wholeNumber(performanceWindowDays, "performance window"));
			// Absent means this form did not offer the choice: leave it as it is.
			if (statusComments != null) {
				settingsService.updateStatusComments(statusComments);
			}
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully updated PR settings");
		} catch (IllegalArgumentException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/prsettings";
	}

	@PostMapping("/update-sync-frequency")
	@PreAuthorize("hasAuthority('" + CorePrivilege.PR_SETTINGS_MODIFY_NAME + "')")
	public String updateSyncFrequency(@RequestParam String syncFrequencyHours,
			RedirectAttributes redirectAttributes) {
		try {
			settingsService.updateSyncFrequencyHours(wholeNumber(syncFrequencyHours, "sync frequency"));
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully updated Pull Request Data Sync frequency");
		} catch (IllegalArgumentException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/prsettings";
	}

	@PostMapping("/update-file-threshold")
	@PreAuthorize("hasAuthority('" + CorePrivilege.PR_SETTINGS_MODIFY_NAME + "')")
	public String updateFileThreshold(@RequestParam String fullSourceFileThreshold,
			RedirectAttributes redirectAttributes) {
		try {
			settingsService.updateFullSourceFileThreshold(wholeNumber(fullSourceFileThreshold, "file threshold"));
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully updated the full-source download threshold");
		} catch (IllegalArgumentException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/prsettings";
	}

	@PostMapping("/update-performance-window")
	@PreAuthorize("hasAuthority('" + CorePrivilege.PR_SETTINGS_MODIFY_NAME + "')")
	public String updatePerformanceWindow(@RequestParam String performanceWindowDays,
			RedirectAttributes redirectAttributes) {
		try {
			settingsService.updatePerformanceWindowDays(wholeNumber(performanceWindowDays, "performance window"));
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully updated the PR performance window");
		} catch (IllegalArgumentException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/prsettings";
	}

	/** A whole number, or a message naming the setting; a bare 400 told the person nothing. */
	private static int wholeNumber(String value, String setting) {
		try {
			return Integer.parseInt(StringUtils.trimToEmpty(value));
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("Enter a whole number for the " + setting + ".");
		}
	}
}
