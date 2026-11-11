package com.tracelink.appsec.watchtower.core.scan.code.scm.repo;

import java.time.DayOfWeek;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/**
 * Gathers what the repository scan pages show, each in a few indexed queries: no page reads a
 * report, and lists show severity from the scan rows alone.
 *
 * @author Watchtower
 */
@Service
public class RepoScanViewService {

	public static final int PAGE_SIZE = 50;
	/** Runs with at most this many repositories show their scanners and findings on the Runs list. */
	static final int RUN_DETAIL_LIMIT = 25;

	static final int QUEUE_ROWS = 50;

	private static final ObjectMapper MAPPER = new ObjectMapper();

	private final RepoScanRepository scans;

	private final RepoScanPlanRepository plans;

	private final ApiIntegrationService integrations;

	private final AsyncJobService jobs;
	@Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService remoteAssessments;

	public com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.RepositoryAdmissionBlocker repositoryAdmissionBlocker() {
		return remoteAssessments == null ? null : remoteAssessments.repositoryAdmissionBlocker().orElse(null);
	}

	@Autowired
	public RepoScanViewService(RepoScanRepository scans,
			RepoScanPlanRepository plans, ApiIntegrationService integrations,
			AsyncJobService jobs) {
		this.scans = scans;
		this.plans = plans;
		this.integrations = integrations;
		this.jobs = jobs;
	}

	/**
	 * @return the source code integrations, sorted
	 */
	public List<String> scmIntegrations() {
		return integrations.getAllSettings().stream()
				.filter(i -> CodeScanType.PULL_REQUEST.equals(i.getScanType()))
				.map(ApiIntegrationEntity::getApiLabel).sorted().toList();
	}

	/**
	 * Plans that have run, most recent first, each with its latest run's progress.
	 */
	public Page<RunSummary> recentRuns(int page) {
		Page<RepoScanPlanEntity> ran = plans.findByRunCountGreaterThan(0,
				PageRequest.of(Math.max(0, page), PAGE_SIZE,
						Sort.by(Sort.Direction.DESC, "lastRunAt")));
		List<Long> ids = ran.stream().map(RepoScanPlanEntity::getId).toList();
		Map<Long, Map<ScanStatus, Long>> latest = new HashMap<>();
		if (!ids.isEmpty()) {
			Map<Long, Integer> runOf = ran.stream().collect(Collectors.toMap(
					RepoScanPlanEntity::getId, RepoScanPlanEntity::getRunCount));
			for (Object[] row : scans.countRunStatuses(ids)) {
				long planId = (Long) row[0];
				if (runOf.get(planId) == ((Integer) row[1]).intValue()) {
					latest.computeIfAbsent(planId, id -> new HashMap<>())
							.merge((ScanStatus) row[2], (Long) row[3], Long::sum);
				}
			}
		}
		return ran.map(plan -> new RunSummary(plan, latest.getOrDefault(plan.getId(),
				Map.of())));
	}

	/**
	 * Status, findings and scanners for each run on a Runs page (UAT #32). Runs of up to
	 * {@value #RUN_DETAIL_LIMIT} repositories are loaded in one query; larger runs are summarized
	 * from their status counts so a page of big plans stays light.
	 */
	public Map<Long, RunOverview> runOverviews(List<RunSummary> runs) {
		List<Long> small = runs.stream().filter(run -> run.total() > 0 && run.total() <= RUN_DETAIL_LIMIT)
				.map(run -> run.plan().getId()).toList();
		Map<Long, List<RepoScanEntity>> byPlan = small.isEmpty() ? Map.of()
				: scans.findLatestRuns(small).stream().collect(Collectors.groupingBy(RepoScanEntity::getPlanId));
		Map<Long, RunOverview> overviews = new HashMap<>();
		for (RunSummary run : runs) {
			long planId = run.plan().getId();
			overviews.put(planId, RunOverview.of(run.statuses(),
					small.contains(planId) ? byPlan.getOrDefault(planId, List.of()) : null));
		}
		return Map.copyOf(overviews);
	}

	public Page<RepoScanPlanEntity> recurringPlans(int page) {
		return plans.findByFrequencyNot(PlanFrequency.ONCE, PageRequest.of(Math.max(0, page),
				PAGE_SIZE, Sort.by("name")));
	}

	/**
	 * @return the first {@value #QUEUE_ROWS} scans waiting or running, oldest first, with their
	 *         repository
	 */
	public List<RepoScanEntity> queuedScans() {
		return scans.findQueue(List.of(ScanStatus.IN_PROGRESS, ScanStatus.NOT_STARTED),
				PageRequest.of(0, QUEUE_ROWS));
	}

	/**
	 * @return the plans of the given scans by id, so each row can name its run
	 */
	public Map<Long, RepoScanPlanEntity> plansOf(List<RepoScanEntity> rows) {
		return plans.findAllById(rows.stream().map(RepoScanEntity::getPlanId).distinct().toList())
				.stream().collect(Collectors.toMap(RepoScanPlanEntity::getId, p -> p));
	}

	/**
	 * @return when a recurring plan runs, e.g. "Weekly on Monday at 02:00 UTC"
	 */
	public static String schedule(RepoScanPlanEntity plan) {
		String at = String.format("at %02d:00 UTC",
				plan.getScheduleHour() == null ? 0 : plan.getScheduleHour());
		Integer day = plan.getScheduleDay();
		return switch (plan.getFrequency()) {
			case WEEKLY -> "Weekly on " + (day == null ? "Monday" : StringUtils.capitalize(
					DayOfWeek.of(Math.clamp(day, 1, 7)).name().toLowerCase(Locale.ROOT))) + " "
					+ at;
			case MONTHLY -> "Monthly on day " + (day == null ? 1 : day) + " " + at;
			case DAILY -> "Daily " + at;
			case ONCE -> "Once";
		};
	}

	public long countScans(ScanStatus status) {
		return scans.countByStatus(status);
	}

	/**
	 * @return the most recently finished scans (done or failed), newest first, with their
	 *         repository: two small indexed reads, merged here
	 */
	public List<RepoScanEntity> latestFinished(int limit) {
		PageRequest first = PageRequest.of(0, limit);
		return Stream.concat(scans.findLatest(ScanStatus.DONE, first).stream(),
				scans.findLatest(ScanStatus.FAILED, first).stream())
				.sorted(Comparator.comparingLong(RepoScanEntity::getEndDate).reversed())
				.limit(limit).toList();
	}

	/**
	 * @return scans submitted in the window that failed or have not finished
	 */
	public long countIncomplete(long start, long end) {
		return scans.countByStatusInAndSubmitDateBetween(List.of(ScanStatus.FAILED,
				ScanStatus.IN_PROGRESS, ScanStatus.NOT_STARTED), start, end);
	}

	/** Queued and running background jobs, oldest first, in plain words. */
	public List<QueueJobView> activeJobs() {
		return jobs.getActiveJobs().stream().map(QueueJobView::of).toList();
	}

	/** Recently finished background jobs of the chosen kind, newest first, in plain words. */
	public List<QueueJobView> recentJobs(QueueJobView.Filter filter) {
		return jobs.getRecentJobs(filter.types()).stream().map(QueueJobView::of).toList();
	}

	/** How many plans have run, for the Runs tab's count. */
	public long countRuns() {
		return plans.countByRunCountGreaterThan(0);
	}

	/** How many recurring plans there are, for the Plans tab's count. */
	public long countPlans() {
		return plans.countByFrequencyNot(PlanFrequency.ONCE);
	}

	/**
	 * @return a scan's findings per rule, most frequent first, from its row alone
	 */
	public static List<Map.Entry<String, Integer>> ruleCounts(RepoScanEntity scan) {
		if (StringUtils.isBlank(scan.getRuleCounts())) {
			return List.of();
		}
		try {
			Map<String, Integer> counts = MAPPER.readValue(scan.getRuleCounts(),
					new TypeReference<Map<String, Integer>>() {
					});
			return counts.entrySet().stream()
					.sorted(Map.Entry.<String, Integer>comparingByValue().reversed()).toList();
		} catch (Exception e) {
			return List.of();
		}
	}

	/**
	 * A plan and the progress of its latest run.
	 *
	 * @param plan     the plan
	 * @param statuses scans of the latest run by status
	 */
	public record RunSummary(RepoScanPlanEntity plan, Map<ScanStatus, Long> statuses) {

		public long total() {
			return statuses.values().stream().mapToLong(Long::longValue).sum();
		}

		public long count(String status) {
			return statuses.getOrDefault(ScanStatus.valueOf(status), 0L);
		}
	}
}
