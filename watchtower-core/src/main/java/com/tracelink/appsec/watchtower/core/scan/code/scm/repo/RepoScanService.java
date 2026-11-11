package com.tracelink.appsec.watchtower.core.scan.code.scm.repo;

import java.time.Clock;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.CatalogSyncHandler;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan.BranchSelector;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan.ExpandPlanHandler;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan.PlanSchedule;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan.RepoSelector;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;

/**
 * Starts repository scan work. Every entry point returns at once: it records a plan and queues
 * a job, and the queue does the slow part (listing repositories, resolving branches, scanning).
 *
 * @author Watchtower
 */
@Service
public class RepoScanService {

	private static final Logger LOG = LoggerFactory.getLogger(RepoScanService.class);

	private static final int MAX_NAME_LENGTH = 255;

	/** How long a default plan name built from its selector may grow. */
	private static final int MAX_DEFAULT_NAME = 80;

	/** How often "Run now" retries when another start took the run number first. */
	private static final int MAX_RUN_ATTEMPTS = 5;

	private static final int MAX_STALE_DAYS = 3650;

	private final RepoScanPlanRepository plans;

	private final AsyncJobService jobs;

	private final ApiIntegrationService integrations;

	private final RulesetService rulesets;

	private final RepoScanSettingsService settings;

	private final ZoneId zone;

	private final Clock clock;

	@Autowired
	public RepoScanService(RepoScanPlanRepository plans, AsyncJobService jobs,
			ApiIntegrationService integrations, RulesetService rulesets,
			RepoScanSettingsService settings,
			@Value("${watchtower.reposcan.zone:UTC}") String zone) {
		this(plans, jobs, integrations, rulesets, settings, ZoneId.of(zone), Clock.systemUTC());
	}

	RepoScanService(RepoScanPlanRepository plans, AsyncJobService jobs,
			ApiIntegrationService integrations, RulesetService rulesets,
			RepoScanSettingsService settings, ZoneId zone, Clock clock) {
		this.plans = plans;
		this.jobs = jobs;
		this.integrations = integrations;
		this.rulesets = rulesets;
		this.settings = settings;
		this.zone = zone;
		this.clock = clock;
	}

	/**
	 * What to scan and when, as submitted from the UI or REST.
	 *
	 * @param name           the plan's name; blank for an automatic one
	 * @param apiLabel       the SCM integration
	 * @param repoSelector   see {@link RepoSelector}
	 * @param branchSelector see {@link BranchSelector}; blank for default branches
	 * @param rulesetId      null to use each repository's own ruleset
	 * @param frequency      once now, or recurring
	 * @param hour           hour of day for a recurring plan
	 * @param day            day of week or month for a weekly or monthly plan
	 * @param skipStaleDays  skip repositories with no commit in this many days; null for none
	 */
	public record PlanRequest(String name, String apiLabel, String repoSelector,
			String branchSelector, Long rulesetId, PlanFrequency frequency, Integer hour,
			Integer day, Integer skipStaleDays) {
	}

	/**
	 * Records a plan. A one-off plan starts its run now; a recurring plan waits for its first
	 * scheduled time.
	 *
	 * @return the saved plan
	 * @throws IllegalArgumentException if the request is not valid
	 */
	public RepoScanPlanEntity submit(PlanRequest request, String user) {
		validate(request);
		long now = clock.millis();
		RepoScanPlanEntity plan = new RepoScanPlanEntity();
		List<String> selector = RepoSelector.tokens(request.repoSelector());
		plan.setName(StringUtils.defaultIfBlank(StringUtils.trim(request.name()),
				defaultName(selector)));
		plan.setApiLabel(request.apiLabel());
		plan.setRepoSelector(String.join("\n", selector));
		plan.setBranchSelector(StringUtils.trimToNull(request.branchSelector()));
		plan.setRulesetId(request.rulesetId());
		plan.setFrequency(request.frequency());
		plan.setScheduleHour(request.hour());
		plan.setScheduleDay(request.day());
		plan.setSkipStaleDays(request.skipStaleDays());
		plan.setNextRunAt(PlanSchedule.next(request.frequency(), request.hour(), request.day(),
				now, zone));
		plan.setCreatedBy(user);
		plan.setCreatedAt(now);
		plan = plans.saveAndFlush(plan);
		LOG.info("{} created repository scan plan {} ({})", user, plan.getId(),
				plan.getFrequency());
		if (!plan.getFrequency().isRecurring()) {
			runNow(plan.getId(), user);
		}
		return plan;
	}

	/**
	 * Starts a run of a plan now, outside its schedule.
	 *
	 * @return the job preparing the run, or empty if the same run is already being prepared
	 */
	public Optional<AsyncJobEntity> runNow(long planId, String user) {
		// Numbered by a compare-and-set on the run count, so two presses (or pods) at once never
		// give two runs one number; the loser reads the new count and takes the next
		for (int attempt = 0; attempt < MAX_RUN_ATTEMPTS; attempt++) {
			RepoScanPlanEntity plan = plans.findById(planId)
					.orElseThrow(() -> new IllegalArgumentException("Unknown plan"));
			if (plans.startRun(planId, plan.getRunCount(), clock.millis()) == 1) {
				return enqueueExpand(planId, plan.getRunCount() + 1, user);
			}
		}
		throw new IllegalArgumentException("The plan is being started elsewhere; try again");
	}

	/**
	 * @return the name of a plan nobody named: what it scans
	 */
	static String defaultName(List<String> selector) {
		if (selector.equals(List.of(RepoSelector.ALL))) {
			return "All repositories";
		}
		if (selector.stream().allMatch(token -> token.toLowerCase(Locale.ROOT)
				.startsWith(RepoSelector.ID_PREFIX))) {
			return selector.size() == 1 ? "1 repository" : selector.size() + " repositories";
		}
		return StringUtils.abbreviate(String.join(", ", selector), MAX_DEFAULT_NAME);
	}

	/**
	 * Starts a recurring plan's due run, unless another pod already started it.
	 *
	 * @return true if this call started the run
	 */
	public boolean startScheduledRun(RepoScanPlanEntity plan, long now) {
		Long next = PlanSchedule.next(plan.getFrequency(), plan.getScheduleHour(),
				plan.getScheduleDay(), now, zone);
		if (next == null || plan.getNextRunAt() == null || plans.claimRun(plan.getId(),
				plan.getNextRunAt(), plan.getRunCount(), next, now) == 0) {
			return false;
		}
		enqueueExpand(plan.getId(), plan.getRunCount() + 1, null);
		return true;
	}

	public void setEnabled(long planId, boolean enabled) {
		RepoScanPlanEntity plan = plans.findById(planId)
				.orElseThrow(() -> new IllegalArgumentException("Unknown plan"));
		plan.setEnabled(enabled);
		if (enabled) {
			plan.setNextRunAt(PlanSchedule.next(plan.getFrequency(), plan.getScheduleHour(),
					plan.getScheduleDay(), clock.millis(), zone));
		}
		plans.saveAndFlush(plan);
	}

	/**
	 * Deletes a plan and its scan rows. Their stored reports expire with retention.
	 */
	public void delete(long planId, String user) {
		plans.deleteById(planId);
		LOG.info("{} deleted repository scan plan {}", user, planId);
	}

	/** @return whether a repository list refresh is waiting or running, so the page can show it */
	public boolean isSyncRunning() {
		return jobs.hasActive(AsyncJobType.CATALOG_SYNC, AsyncJobService.STUCK_AFTER_MILLIS);
	}

	/**
	 * Queues a repository list refresh of every SCM integration.
	 *
	 * @param user who asked, or null for the schedule
	 * @return the jobs queued; an integration already syncing is skipped
	 */
	public List<AsyncJobEntity> requestSync(String user) {
		// A sync whose queue message was lost would otherwise refuse this request as "already running".
		jobs.expireStalledQueued(List.of(AsyncJobType.CATALOG_SYNC), AsyncJobService.STUCK_AFTER_MILLIS);
		List<AsyncJobEntity> queued = new ArrayList<>();
		for (ApiIntegrationEntity integration : integrations.getAllSettings()) {
			if (CodeScanType.PULL_REQUEST.equals(integration.getScanType())) {
				jobs.enqueue(AsyncJobType.CATALOG_SYNC,
						CatalogSyncHandler.payload(integration.getApiLabel()),
						"sync-" + integration.getApiLabel(), user).ifPresent(queued::add);
			}
		}
		settings.recordSync(clock.millis());
		return queued;
	}

	private Optional<AsyncJobEntity> enqueueExpand(long planId, int runNo, String user) {
		return jobs.enqueue(AsyncJobType.EXPAND_PLAN, ExpandPlanHandler.payload(planId, runNo),
				"expand-" + planId + "-" + runNo, user);
	}

	private void validate(PlanRequest request) {
		if (request.frequency() == null) {
			throw new IllegalArgumentException("Choose when to scan");
		}
		if (StringUtils.length(request.name()) > MAX_NAME_LENGTH) {
			throw new IllegalArgumentException("The name is too long");
		}
		ApiIntegrationEntity integration = integrations.findByLabel(request.apiLabel());
		if (integration == null
				|| !CodeScanType.PULL_REQUEST.equals(integration.getScanType())) {
			throw new IllegalArgumentException("Unknown source code integration");
		}
		RepoSelector.tokens(request.repoSelector());
		BranchSelector.validate(request.branchSelector());
		PlanSchedule.validate(request.frequency(), request.hour(), request.day());
		Integer stale = request.skipStaleDays();
		if (stale != null && (stale < 1 || stale > MAX_STALE_DAYS)) {
			throw new IllegalArgumentException("Skip stale must be 1 to " + MAX_STALE_DAYS
					+ " days");
		}
		if (request.rulesetId() != null) {
			try {
				rulesets.getRuleset(request.rulesetId());
			} catch (RulesetNotFoundException e) {
				throw new IllegalArgumentException("Unknown ruleset");
			}
		}
	}
}
