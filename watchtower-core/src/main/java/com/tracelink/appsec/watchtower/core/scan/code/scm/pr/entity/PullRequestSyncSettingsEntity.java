package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Singleton settings row governing {@link
 * com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSynchronizer}'s
 * sync cadence (IMPROVEMENT_PLAN.md item 5.2). Admin-editable at runtime via
 * {@code PullRequestSyncSettingsService} - no application restart required to change
 * {@code syncFrequencyHours}, since {@code PullRequestSynchronizer} re-reads this row on
 * every scheduled tick rather than baking the interval into a {@code @Scheduled} annotation.
 */
@Entity
@Table(name = "pull_request_sync_settings")
public class PullRequestSyncSettingsEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "settings_id")
	private long id;

	@Column(name = "sync_frequency_hours")
	private int syncFrequencyHours = 24;

	// Minutes between syncs; null on rows saved before minutes existed, which fall back to their hours.
	@Column(name = "sync_frequency_minutes")
	private Integer syncFrequencyMinutes = 15;

	@Column(name = "last_sync_completed_at")
	private Long lastSyncCompletedAt;

	// Changed-file count above which a PR scan (PRScanAgent.collectFiles()) downloads the
	// full repository instead of fetching each changed file individually from the SCM.
	@Column(name = "full_source_file_threshold")
	private int fullSourceFileThreshold = 5;

	@Column(name = "performance_window_days")
	private int performanceWindowDays = 7;

	// Whether Watchtower keeps one status comment on each pull request, edited as its scan progresses.
	@Column(name = "status_comments_enabled")
	private boolean statusCommentsEnabled = true;

	public long getId() {
		return id;
	}

	public boolean isStatusCommentsEnabled() {
		return statusCommentsEnabled;
	}

	public void setStatusCommentsEnabled(boolean statusCommentsEnabled) {
		this.statusCommentsEnabled = statusCommentsEnabled;
	}

	public int getSyncFrequencyHours() {
		return syncFrequencyHours;
	}

	public void setSyncFrequencyHours(int syncFrequencyHours) {
		this.syncFrequencyHours = syncFrequencyHours;
		this.syncFrequencyMinutes = syncFrequencyHours * 60;
	}

	/** Minutes between syncs. */
	public int getSyncFrequencyMinutes() {
		return syncFrequencyMinutes != null ? syncFrequencyMinutes : syncFrequencyHours * 60;
	}

	public void setSyncFrequencyMinutes(int minutes) {
		this.syncFrequencyMinutes = minutes;
		this.syncFrequencyHours = Math.max(1, (minutes + 59) / 60);
	}

	public Long getLastSyncCompletedAt() {
		return lastSyncCompletedAt;
	}

	public void setLastSyncCompletedAt(Long lastSyncCompletedAt) {
		this.lastSyncCompletedAt = lastSyncCompletedAt;
	}

	public int getFullSourceFileThreshold() {
		return fullSourceFileThreshold;
	}

	public void setFullSourceFileThreshold(int fullSourceFileThreshold) {
		this.fullSourceFileThreshold = fullSourceFileThreshold;
	}

	public int getPerformanceWindowDays() {
		return performanceWindowDays;
	}

	public void setPerformanceWindowDays(int performanceWindowDays) {
		this.performanceWindowDays = performanceWindowDays;
	}
}
