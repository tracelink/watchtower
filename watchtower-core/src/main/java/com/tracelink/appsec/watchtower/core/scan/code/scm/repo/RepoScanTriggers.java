package com.tracelink.appsec.watchtower.core.scan.code.scm.repo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.IntegrationHealthHandler;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.IntegrationHealthService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;

import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

/**
 * The repository scan schedule. Only queues work, so each tick is quick: a repository list
 * refresh when one is due, the runs of plans whose time has come, an integration connection
 * check every six hours, and cleanup of old job rows.
 * Runs on one pod at a time.
 *
 * @author Watchtower
 */
@Component
public class RepoScanTriggers {

	private static final Logger LOG = LoggerFactory.getLogger(RepoScanTriggers.class);

	static final int JOB_RETENTION_DAYS = 30;

	private final RepoScanSettingsService settings;

	private final RepoScanService service;

	private final RepoScanPlanRepository plans;

	private final AsyncJobService jobs;

	private final ApiIntegrationService integrations;

	private final IntegrationHealthService health;

	private final boolean enabled;

	@Autowired
	public RepoScanTriggers(RepoScanSettingsService settings, RepoScanService service,
			RepoScanPlanRepository plans, AsyncJobService jobs,
			ApiIntegrationService integrations, IntegrationHealthService health,
			@Value("${watchtower.reposcan.triggers-enabled:true}") boolean enabled) {
		this.settings = settings;
		this.service = service;
		this.plans = plans;
		this.jobs = jobs;
		this.integrations = integrations;
		this.health = health;
		this.enabled = enabled;
	}

	@Scheduled(initialDelayString = "${watchtower.reposcan.trigger-initial-delay-ms:120000}",
			fixedDelayString = "${watchtower.reposcan.trigger-delay-ms:300000}")
	@SchedulerLock(name = "repo-scan-triggers", lockAtMostFor = "PT4M")
	public void fire() {
		if (!enabled) {
			return;
		}
		try {
			// A sync or check whose queue message was lost keeps its dedup key and refuses every later
			// request as "already running"; drop such a job before asking for a new one.
			jobs.expireStalledQueued(
					java.util.List.of(AsyncJobType.CATALOG_SYNC, AsyncJobType.INTEGRATION_HEALTH),
					AsyncJobService.STUCK_AFTER_MILLIS);
		} catch (RuntimeException e) {
			LOG.warn("Could not drop stalled queued jobs", e);
		}
		try {
			if (settings.isSyncDue()) {
				service.requestSync(null);
			}
		} catch (RuntimeException e) {
			LOG.error("Could not queue the repository list refresh", e);
		}
		long now = System.currentTimeMillis();
		for (RepoScanPlanEntity plan : plans.findDue(now, PlanFrequency.ONCE)) {
			try {
				if (service.startScheduledRun(plan, now)) {
					LOG.info("Started scheduled run of repository scan plan {}", plan.getId());
				}
			} catch (RuntimeException e) {
				LOG.error("Could not start repository scan plan " + plan.getId(), e);
			}
		}
		try {
			// Due when an integration was never checked or not for six hours; the dedup key
			// keeps one check job in flight across pods
			if (health.isCheckDue(integrations.getAllSettings())) {
				jobs.enqueue(AsyncJobType.INTEGRATION_HEALTH, "{}",
						IntegrationHealthHandler.DEDUP_KEY, null);
			}
		} catch (RuntimeException e) {
			LOG.warn("Could not queue the integration check", e);
		}
		try {
			jobs.deleteFinishedOlderThan(JOB_RETENTION_DAYS);
		} catch (RuntimeException e) {
			LOG.warn("Could not clean up finished jobs", e);
		}
	}
}
