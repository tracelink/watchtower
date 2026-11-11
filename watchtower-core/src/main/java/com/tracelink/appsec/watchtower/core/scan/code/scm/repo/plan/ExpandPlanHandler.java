package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobHandler;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.RepoWorkQueue;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.presentation.PluralText;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/**
 * Turns one run of a plan into queued scans: resolves the plan's repositories and branches,
 * writes a scan row for each, and queues them most critical first. Runs as a job because
 * resolving branch patterns takes an SCM call per repository. Running a run twice (a redelivered
 * message) queues its existing rows again instead of creating duplicates.
 *
 * @author Watchtower
 */
@Component
public class ExpandPlanHandler implements AsyncJobHandler {

	private static final Logger LOG = LoggerFactory.getLogger(ExpandPlanHandler.class);

	private static final ObjectMapper MAPPER = new ObjectMapper();

	private static final long DAY_MILLIS = 86_400_000L;

	private final RepoScanPlanRepository plans;

	private final RepositoryRepository repositories;

	private final RepoScanRepository scans;

	private final ApiIntegrationService integrations;

	private final RepoWorkQueue queue;

	private final int maxRepositories;

	private final int maxBranches;

	private final Clock clock;

	@Autowired
	public ExpandPlanHandler(RepoScanPlanRepository plans, RepositoryRepository repositories,
			RepoScanRepository scans, ApiIntegrationService integrations, RepoWorkQueue queue,
			@Value("${watchtower.reposcan.max-repos-per-run:500}") int maxRepositories,
			@Value("${watchtower.reposcan.max-branches-per-repo:5}") int maxBranches) {
		this(plans, repositories, scans, integrations, queue, maxRepositories, maxBranches,
				Clock.systemUTC());
	}

	ExpandPlanHandler(RepoScanPlanRepository plans, RepositoryRepository repositories,
			RepoScanRepository scans, ApiIntegrationService integrations, RepoWorkQueue queue,
			int maxRepositories, int maxBranches, Clock clock) {
		this.plans = plans;
		this.repositories = repositories;
		this.scans = scans;
		this.integrations = integrations;
		this.queue = queue;
		this.maxRepositories = maxRepositories;
		this.maxBranches = maxBranches;
		this.clock = clock;
	}

	@Override
	public AsyncJobType type() {
		return AsyncJobType.EXPAND_PLAN;
	}

	/**
	 * @return the job payload naming one run of a plan
	 */
	public static String payload(long planId, int runNo) {
		return MAPPER.createObjectNode().put("planId", planId).put("runNo", runNo).toString();
	}

	@Override
	public String handle(AsyncJobEntity job, Consumer<String> progress) throws Exception {
		JsonNode payload = MAPPER.readTree(job.getPayload());
		long planId = payload.path("planId").asLong();
		int runNo = payload.path("runNo").asInt();
		RepoScanPlanEntity plan = plans.findById(planId)
				.orElseThrow(() -> new IllegalStateException("Plan " + planId + " was deleted"));

		List<RepoScanEntity> existing = scans.findRun(planId, runNo);
		if (!existing.isEmpty()) {
			existing.stream().filter(s -> s.getStatus() == ScanStatus.NOT_STARTED)
					.forEach(s -> queue.sendScan(s.getId()));
			progress.accept(PluralText.count(existing.size(), "scan") + " queued");
			return null;
		}
		List<RepositoryEntity> chosen = choose(plan);
		IScmApi api = api(plan.getApiLabel());
		List<RepoScanEntity> rows = new ArrayList<>();
		long now = clock.millis();
		for (RepositoryEntity repo : chosen) {
			for (String branch : BranchSelector.resolve(plan.getBranchSelector(),
					repo.getDefaultBranch(), api, repo.getRepoName(), maxBranches)) {
				rows.add(row(plan, runNo, repo, branch, now));
			}
		}
		List<RepoScanEntity> saved = scans.saveAll(rows);
		saved.forEach(scan -> queue.sendScan(scan.getId()));
		String summary = PluralText.count(saved.size(), "scan") + " queued across "
				+ PluralText.count(chosen.size(), "repository", "repositories");
		LOG.info("Plan {} run {}: {}", planId, runNo, summary);
		progress.accept(summary);
		return null;
	}

	private List<RepositoryEntity> choose(RepoScanPlanEntity plan) {
		List<RepositoryEntity> candidates = repositories
				.findByScanTypeAndApiLabelAndEnabledTrue(CodeScanType.PULL_REQUEST,
						plan.getApiLabel());
		Integer staleDays = plan.getSkipStaleDays();
		long staleBefore = staleDays == null ? 0 : clock.millis() - staleDays * DAY_MILLIS;
		List<RepositoryEntity> chosen = RepoSelector.resolve(plan.getRepoSelector(), candidates)
				.stream()
				.filter(r -> !r.isScanningPaused())
				.filter(r -> staleDays == null || r.getLastCommitAt() == 0
						|| r.getLastCommitAt() >= staleBefore)
				.toList();
		if (chosen.size() > maxRepositories) {
			LOG.warn("Plan {} matched {} repositories; scanning the first {}", plan.getId(),
					chosen.size(), maxRepositories);
			return chosen.subList(0, maxRepositories);
		}
		return chosen;
	}

	private static RepoScanEntity row(RepoScanPlanEntity plan, int runNo, RepositoryEntity repo,
			String branch, long now) {
		RepoScanEntity scan = new RepoScanEntity();
		scan.setPlanId(plan.getId());
		scan.setRunNo(runNo);
		scan.setRepository(repo);
		scan.setBranch(branch);
		scan.setStatus(ScanStatus.NOT_STARTED);
		scan.setPriority(repo.getCriticality());
		scan.setSubmitDate(now);
		return scan;
	}

	private IScmApi api(String apiLabel) {
		ApiIntegrationEntity integration = integrations.findByLabel(apiLabel);
		if (integration == null || !(integration.createApi() instanceof IScmApi api)) {
			throw new IllegalStateException("Integration " + apiLabel + " is not configured");
		}
		return api;
	}
}
