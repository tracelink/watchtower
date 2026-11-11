package com.tracelink.appsec.watchtower.core.scan.code.scm.repo;

import java.time.Clock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanSettingsRepository;

/**
 * Repository scan settings shared by every pod. The pause flag is read on every queue poll, so
 * it is cached for a few seconds: a pause reaches every pod within that time without a query
 * per poll.
 *
 * @author Watchtower
 */
@Service
public class RepoScanSettingsService {

	private static final Logger LOG = LoggerFactory.getLogger(RepoScanSettingsService.class);

	static final long CACHE_MILLIS = 10_000;

	private static final int MIN_SYNC_HOURS = 1;

	private static final int MAX_SYNC_HOURS = 24 * 7;

	private final RepoScanSettingsRepository repository;

	private final Clock clock;

	private volatile RepoScanSettingsEntity cached;

	private volatile long cachedAt;

	@Autowired
	public RepoScanSettingsService(RepoScanSettingsRepository repository) {
		this(repository, Clock.systemUTC());
	}

	RepoScanSettingsService(RepoScanSettingsRepository repository, Clock clock) {
		this.repository = repository;
		this.clock = clock;
	}

	public RepoScanSettingsEntity getSettings() {
		long now = clock.millis();
		RepoScanSettingsEntity current = cached;
		if (current == null || now - cachedAt > CACHE_MILLIS) {
			current = repository.findById(RepoScanSettingsEntity.SINGLETON_ID)
					.orElseGet(() -> repository.saveAndFlush(new RepoScanSettingsEntity()));
			cached = current;
			cachedAt = now;
		}
		return current;
	}

	public boolean isPaused() {
		return getSettings().isPaused();
	}

	/**
	 * Pauses or resumes repository scans on every pod. A running scan finishes; queued work
	 * waits.
	 *
	 * @param paused true to pause
	 * @param user   who changed it, for the log
	 */
	public void setPaused(boolean paused, String user) {
		RepoScanSettingsEntity settings = fresh();
		settings.setPaused(paused);
		save(settings);
		LOG.info("Repository scans {} by {}", paused ? "paused" : "resumed", user);
	}

	/**
	 * @param hours how often each integration's repository list is refreshed, 1-168
	 * @throws IllegalArgumentException if out of range
	 */
	public void setSyncFrequencyHours(int hours) {
		if (hours < MIN_SYNC_HOURS || hours > MAX_SYNC_HOURS) {
			throw new IllegalArgumentException(
					"Sync frequency must be between 1 and " + MAX_SYNC_HOURS + " hours");
		}
		RepoScanSettingsEntity settings = fresh();
		settings.setSyncFrequencyHours(hours);
		save(settings);
	}

	public void recordSync(long when) {
		RepoScanSettingsEntity settings = fresh();
		settings.setLastSyncAt(when);
		save(settings);
	}

	/**
	 * @return true if the repository lists are due a refresh
	 */
	public boolean isSyncDue() {
		RepoScanSettingsEntity settings = getSettings();
		return clock.millis() - settings.getLastSyncAt()
				>= settings.getSyncFrequencyHours() * 3_600_000L;
	}

	private RepoScanSettingsEntity fresh() {
		cached = null;
		return getSettings();
	}

	private void save(RepoScanSettingsEntity settings) {
		cached = repository.saveAndFlush(settings);
		cachedAt = clock.millis();
	}
}
