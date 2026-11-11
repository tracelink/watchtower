package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * The single row of repository scan settings. Kept in the database rather than in memory so
 * every pod sees the same pause state and sync schedule.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "repo_scan_settings")
public class RepoScanSettingsEntity {

	public static final long SINGLETON_ID = 1L;

	@Id
	@Column(name = "settings_id")
	private long id = SINGLETON_ID;

	@Column(name = "paused")
	private boolean paused;

	@Column(name = "sync_frequency_hours")
	private int syncFrequencyHours = 6;

	@Column(name = "last_sync_at")
	private Long lastSyncAt;

	public long getId() {
		return id;
	}

	public boolean isPaused() {
		return paused;
	}

	public void setPaused(boolean paused) {
		this.paused = paused;
	}

	public int getSyncFrequencyHours() {
		return syncFrequencyHours;
	}

	public void setSyncFrequencyHours(int syncFrequencyHours) {
		this.syncFrequencyHours = syncFrequencyHours;
	}

	public long getLastSyncAt() {
		return lastSyncAt == null ? 0 : lastSyncAt;
	}

	public void setLastSyncAt(long lastSyncAt) {
		this.lastSyncAt = lastSyncAt;
	}
}
