package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PullRequestSyncSettingsRepository;

/**
 * Manages the singleton {@link PullRequestSyncSettingsEntity} row that governs
 * {@link PullRequestSynchronizer}'s sync cadence (IMPROVEMENT_PLAN.md item 5.2). Always reads
 * fresh from the database rather than caching, matching this codebase's convention for
 * admin-editable settings (e.g. {@code ApiIntegrationService}).
 */
@Service
public class PullRequestSyncSettingsService {

	private final PullRequestSyncSettingsRepository settingsRepository;

	public PullRequestSyncSettingsService(PullRequestSyncSettingsRepository settingsRepository) {
		this.settingsRepository = settingsRepository;
	}

	/**
	 * Gets the settings row, creating one with default values if it does not yet exist.
	 *
	 * @return the settings entity
	 */
	public PullRequestSyncSettingsEntity getSettings() {
		List<PullRequestSyncSettingsEntity> settingsList = settingsRepository.findAll();
		if (settingsList.isEmpty()) {
			return settingsRepository.saveAndFlush(new PullRequestSyncSettingsEntity());
		}
		return settingsList.get(0);
	}

	/**
	 * Updates the configured sync frequency.
	 *
	 * @param hours the new sync frequency, in hours
	 * @throws IllegalArgumentException if {@code hours} is not a positive number
	 */
	public void updateSyncFrequencyHours(int hours) throws IllegalArgumentException {
		if (hours <= 0) {
			throw new IllegalArgumentException(
					"Please provide a sync frequency greater than zero hours");
		}
		PullRequestSyncSettingsEntity settings = getSettings();
		settings.setSyncFrequencyHours(hours);
		settingsRepository.saveAndFlush(settings);
	}

	/** The shortest sync frequency: each sync costs one source control call per open pull request. */
	public static final int MIN_SYNC_MINUTES = 5;

	/**
	 * Updates the configured sync frequency, in minutes.
	 *
	 * @throws IllegalArgumentException if it is below {@link #MIN_SYNC_MINUTES}
	 */
	public void updateSyncFrequencyMinutes(int minutes) throws IllegalArgumentException {
		validateSyncMinutes(minutes);
		PullRequestSyncSettingsEntity settings = getSettings();
		settings.setSyncFrequencyMinutes(minutes);
		settingsRepository.saveAndFlush(settings);
	}

	/** Turns the pull request status comment on or off. */
	public void updateStatusComments(boolean enabled) {
		PullRequestSyncSettingsEntity settings = getSettings();
		if (settings.isStatusCommentsEnabled() == enabled) {
			return;
		}
		settings.setStatusCommentsEnabled(enabled);
		settingsRepository.saveAndFlush(settings);
	}

	private void validateSyncMinutes(int minutes) {
		if (minutes < MIN_SYNC_MINUTES) {
			throw new IllegalArgumentException(
					"Please provide a sync frequency of at least " + MIN_SYNC_MINUTES + " minutes");
		}
	}

	/** Validates and persists every user-editable PR setting as one update, the sync frequency in minutes. */
	public void updateSettingsMinutes(int syncFrequencyMinutes, int fullSourceFileThreshold,
			int performanceWindowDays) throws IllegalArgumentException {
		validateSyncMinutes(syncFrequencyMinutes);
		validateFileThreshold(fullSourceFileThreshold);
		validatePerformanceWindow(performanceWindowDays);
		PullRequestSyncSettingsEntity settings = getSettings();
		settings.setSyncFrequencyMinutes(syncFrequencyMinutes);
		settings.setFullSourceFileThreshold(fullSourceFileThreshold);
		settings.setPerformanceWindowDays(performanceWindowDays);
		settingsRepository.saveAndFlush(settings);
	}

	/**
	 * Updates the changed-file count threshold above which a PR scan downloads the full
	 * repository instead of fetching each changed file individually (see
	 * {@code PRScanAgent.collectFiles()}).
	 *
	 * @param threshold the new threshold, in changed-file count
	 * @throws IllegalArgumentException if {@code threshold} is not a positive number
	 */
	public void updateFullSourceFileThreshold(int threshold) throws IllegalArgumentException {
		if (threshold <= 0) {
			throw new IllegalArgumentException(
					"Please provide a file threshold greater than zero");
		}
		PullRequestSyncSettingsEntity settings = getSettings();
		settings.setFullSourceFileThreshold(threshold);
		settingsRepository.saveAndFlush(settings);
	}

	/** Update the recent-performance window used by the PR dashboard. */
	public void updatePerformanceWindowDays(int days) throws IllegalArgumentException {
		if (days < 1 || days > 365) {
			throw new IllegalArgumentException(
					"Performance window must be between 1 and 365 days");
		}
		PullRequestSyncSettingsEntity settings = getSettings();
		settings.setPerformanceWindowDays(days);
		settingsRepository.saveAndFlush(settings);
	}

	/** Validates and persists every user-editable PR setting as one update. */
	public void updateSettings(int syncFrequencyHours, int fullSourceFileThreshold,
			int performanceWindowDays) throws IllegalArgumentException {
		validateSyncFrequency(syncFrequencyHours);
		validateFileThreshold(fullSourceFileThreshold);
		validatePerformanceWindow(performanceWindowDays);
		PullRequestSyncSettingsEntity settings = getSettings();
		settings.setSyncFrequencyHours(syncFrequencyHours);
		settings.setFullSourceFileThreshold(fullSourceFileThreshold);
		settings.setPerformanceWindowDays(performanceWindowDays);
		settingsRepository.saveAndFlush(settings);
	}

	private void validateSyncFrequency(int hours) {
		if (hours <= 0) {
			throw new IllegalArgumentException(
					"Please provide a sync frequency greater than zero hours");
		}
	}

	private void validateFileThreshold(int threshold) {
		if (threshold <= 0) {
			throw new IllegalArgumentException(
					"Please provide a file threshold greater than zero");
		}
	}

	private void validatePerformanceWindow(int days) {
		if (days < 1 || days > 365) {
			throw new IllegalArgumentException(
					"Performance window must be between 1 and 365 days");
		}
	}

	/**
	 * Records that a sync just completed, so the next scheduled tick knows whether another
	 * sync is due yet.
	 *
	 * @param nowMillis the completion time, in epoch millis
	 */
	public void recordSyncCompleted(long nowMillis) {
		PullRequestSyncSettingsEntity settings = getSettings();
		settings.setLastSyncCompletedAt(nowMillis);
		settingsRepository.saveAndFlush(settings);
	}
}
