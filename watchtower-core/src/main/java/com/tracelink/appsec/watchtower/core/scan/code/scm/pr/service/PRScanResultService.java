package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionWriter;
import com.tracelink.appsec.watchtower.core.rule.RuleChange;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanResultService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeExcerpts;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.AbstractScmIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.FileFetch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanCompletedEvent;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestMCRStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanTimings;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;
import com.tracelink.appsec.watchtower.core.scan.presentation.StatusPresentationModel;

import java.util.*;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Service;

/**
 * Handles logic around storing a retrieving scan results
 *
 * @author csmith
 */
@Service
public class PRScanResultService
		extends AbstractScanResultService<PullRequestScanEntity, PullRequestViolationEntity> {
	/** Called inside provider enlistment's transaction, so parent + child intent commit together. */
	@org.springframework.transaction.annotation.Transactional
	public long reserveRemoteParent(PullRequest pr, long startedAt) {
		var container = prRepo.findFirstByApiLabelAndRepoNameAndPrIdOrderByIdDesc(pr.getApiLabel(), pr.getRepoName(), pr.getPrId());
		if (container == null) container = prRepo.saveAndFlush(new PullRequestContainerEntity(pr));
		var scan = new PullRequestScanEntity(); scan.setContainer(container); scan.setStartDate(startedAt);
		scan.setSubmitDate(pr.getSubmitTime()); scan.setStatus(ScanStatus.IN_PROGRESS); scan.setCommitHash(pr.getCommitHash());
		scan.setRemoteAssessmentState("PENDING");
		return scanRepo.saveAndFlush(scan).getId();
	}
	public boolean remoteParentHasLocalResults(long scanId) {
		return scanId > 0 && scanRepo.findById(Long.valueOf(scanId)).map(PullRequestScanEntity::isPerformanceComplete).orElse(false);
	}

	/**
	 * Name prefix identifying a Malicious Code Review finding. Mirrors the constant in
	 * {@code PRScanAgent}; MCR findings are reported through the MCR views rather than
	 * alongside ordinary violations.
	 */
	private static final String MCR_NAME_PREFIX = "MCR Match:";

	private static final Logger LOG = LoggerFactory.getLogger(PRScanResultService.class);
	private static final ObjectMapper TIMING_MAPPER = new ObjectMapper();

	private final PRContainerRepository prRepo;
	private final RepositoryRepository repoRepo;
	private final PRScanRepository scanRepo;
	private final PRViolationRepository vioRepo;
	private final RuleService ruleService;
	private final ApiIntegrationService apiIntegrationService;
	private final ScanRegistrationService scanRegistrationService;
	private final ApplicationEventPublisher eventPublisher;
 @Autowired(required=false)
 private com.tracelink.appsec.watchtower.core.metrics.RuleMetricWriter ruleMetrics;

	private MetricsProjectionWriter metricsProjectionWriter;

	@Autowired(required = false)
	void setMetricsProjectionWriter(MetricsProjectionWriter writer) {
		this.metricsProjectionWriter = writer;
	}

	public PRScanResultService(
			@Autowired PRContainerRepository prRepo, @Autowired RepositoryRepository repoRepo,
			@Autowired PRScanRepository scanRepo, @Autowired PRViolationRepository vioRepo,
			@Autowired RuleService ruleService,
			@Autowired ApiIntegrationService apiIntegrationService,
			@Autowired ScanRegistrationService scanRegistrationService,
			@Autowired ApplicationEventPublisher eventPublisher) {
		super(scanRepo, vioRepo);
		this.prRepo = prRepo;
		this.repoRepo = repoRepo;
		this.scanRepo = scanRepo;
		this.vioRepo = vioRepo;
		this.ruleService = ruleService;
		this.apiIntegrationService = apiIntegrationService;
		this.scanRegistrationService = scanRegistrationService;
		this.eventPublisher = eventPublisher;
	}

	/**
	 * Store a PR Scan to a backend database
	 *
	 * @param pr              the Pull Request to save
	 * @param startTime       the starting time of the scan
	 * @param violations      the violations found in this scan
	 * @param errors          the errors found in this scan
	 * @param sourceSizeBytes byte size of the source actually scanned
	 * @param timings         phase timings captured by the scan agent
	 */
	public long savePullRequestScan(PullRequest pr, long startTime,
			List<PullRequestViolationEntity> violations, List<CodeScanError> errors,
			long sourceSizeBytes, PRScanTimings timings) {
		return savePullRequestScan(pr, startTime, violations, errors, sourceSizeBytes, timings, null);
	}

	public long savePullRequestScan(PullRequest pr, long startTime,
			List<PullRequestViolationEntity> violations, List<CodeScanError> errors,
			long sourceSizeBytes, PRScanTimings timings, ScanExecutionSummary summary) {
		if (violations == null) {
			return 0;
		}
		long now = System.currentTimeMillis();

		PullRequestContainerEntity prEntity =
				prRepo.findFirstByApiLabelAndRepoNameAndPrIdOrderByIdDesc(pr.getApiLabel(),
						pr.getRepoName(), pr.getPrId());
		if (prEntity == null) {
			prEntity = new PullRequestContainerEntity(pr);
			prEntity = prRepo.saveAndFlush(prEntity);
		}

		prEntity.setLastReviewedDate(now);
		// The state was fetched when the scan started: closed then means nothing was pending at
		// the close (a scan that finishes after a merge shows as one by its end time); open after
		// a recorded close means the pull request was reopened.
		recordClosed(prEntity, pr, now, false);
		prEntity.recordOpen(pr.getState(), pr.getUpdateTime());
		// "Resolved" means the pull request is closed: merged or declined, as the SCM last reported (the two
		// calls above keep that current, including a reopen). A scan with no new findings used to set it too,
		// which showed open pull requests as Resolved, hid them from the default results and kept the sync
		// from ever learning that they merged. A manually submitted pull request without a state stays open
		// until the sync or a webhook closes it.
		prEntity.setResolved(prEntity.getClosedState() != null);
		PullRequestContainerEntity savedPREntity = prRepo.saveAndFlush(prEntity);

		PullRequestScanEntity scanEntity = pr.getExecutionScanId() > 0
				? scanRepo.findById(pr.getExecutionScanId()) : new PullRequestScanEntity();
		if (scanEntity == null) throw new IllegalStateException("Reserved PR execution disappeared");
		scanEntity.setContainer(savedPREntity);
		scanEntity.setEndDate(now);
		scanEntity.setSubmitDate(pr.getSubmitTime());
		scanEntity.setStartDate(startTime);
		scanEntity.setStatus(scanEntity.getRemoteAssessmentState() == null ? ScanStatus.DONE : ScanStatus.IN_PROGRESS);
		if (!errors.isEmpty()) {
			scanEntity.setError(errors.stream().map(CodeScanError::getErrorMessage)
					.collect(Collectors.joining(", ")));
		}
		scanEntity.setMcrStatus(resolveMCRStatus(violations));
		scanEntity.setSourceSizeBytes(sourceSizeBytes);
		scanEntity.setTotalDurationMs(timings.totalMs());
		scanEntity.setQueueWaitDurationMs(timings.queueWaitMs());
		scanEntity.setSourcePreparationDurationMs(timings.sourcePreparationMs());
		scanEntity.setScannerExecutionDurationMs(timings.scannerExecutionMs());
		scanEntity.setResultProcessingDurationMs(timings.resultProcessingMs());
		scanEntity.setScmReportingDurationMs(timings.scmReportingMs());
		scanEntity.setPersistenceDurationMs(timings.persistenceMs());
		scanEntity.setCleanupDurationMs(timings.cleanupMs());
		scanEntity.setPerformanceComplete(timings.complete());
		scanEntity.setChangedFileCount(timings.changedFileCount());
		scanEntity.setScanScope(timings.scanScope());
		scanEntity.setSourceStrategy(timings.sourceStrategy());
		scanEntity.setCommitHash(pr.getCommitHash());
		// Store the final enforcement summary alongside the original per-finding policy.
		scanEntity.setBlocked(violations.stream()
				.anyMatch(v -> v.isBlocking() && v.isNewViolation()));
		try {
			scanEntity.setScannerTimingsJson(TIMING_MAPPER.writeValueAsString(timings.scanners()));
		} catch (JsonProcessingException e) {
			LOG.warn("Could not serialize scanner timings for " + pr.getPRString(), e);
			scanEntity.setScannerTimingsJson("[]");
		}

		applyExecutionSummary(scanEntity, summary);
		PullRequestScanEntity savedScanEntity = scanRepo.saveAndFlush(scanEntity);

		consolidateMCRFindings(violations);

		violations.forEach(v -> {
			v.setScan(savedScanEntity);
			vioRepo.save(v);
		});
		vioRepo.flush();
  if (ruleMetrics != null) {
   try {
    ruleMetrics.recordEntities("pull_request", savedScanEntity.getId(), savedScanEntity.getEndDateMillis(),
      com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec.decode(savedScanEntity.getExecutionSnapshotJson()), violations);
   } catch (RuntimeException e) {
    LOG.warn("Rule identity projection failed for pull_request scan {}", savedScanEntity.getId());
   }
  }
		if (metricsProjectionWriter != null) {
			try {
				metricsProjectionWriter.record("pull_request", savedScanEntity, violations);
			} catch (RuntimeException e) {
				metricsProjectionWriter.recordFailure("pull_request", e);
			}
		}
		publishScanCompleted(savedScanEntity.getId(), pr, violations);
		return savedScanEntity.getId();
	}

	/**
	 * Tells listeners the scan is saved. A listener failure is logged, never rethrown: the scan
	 * is already persisted, and failing here would make SQS redeliver and save it again.
	 *
	 * @param scanId     the saved scan's id
	 * @param pr         the scanned pull request
	 * @param violations the saved violations
	 */
	private void publishScanCompleted(long scanId, PullRequest pr,
			List<PullRequestViolationEntity> violations) {
		try {
			eventPublisher.publishEvent(new PRScanCompletedEvent(scanId, pr,
					violations.stream().map(PRScanCompletedEvent.Finding::of)
							.collect(Collectors.toList())));
		} catch (RuntimeException e) {
			LOG.warn("Scan {} saved, but a scan-completed listener failed for {}", scanId,
					pr.getPRString(), e);
		}
	}

	public void saveExecutionSummary(long scanId, ScanExecutionSummary summary) {
		PullRequestScanEntity entity = scanRepo.findById(scanId);
		if (entity == null || summary == null) return;
		applyExecutionSummary(entity, summary);
		scanRepo.saveAndFlush(entity);
	}

	private void applyExecutionSummary(PullRequestScanEntity entity, ScanExecutionSummary summary) {
		if (summary == null) return;
		entity.setRulesEvaluated(summary.rulesEvaluated());
		entity.setExecutionSnapshotJson(CodeScanExecutionSnapshotCodec.encode(summary.codeSnapshot()));
		// PR run durations already live in scanner_timings_json and power the existing
		// performance report. Also preserve failed/skipped/reused module states here.
		entity.setScannerExecutionsJson(ScanExecutionSummaryCodec.encode(summary.scanners().stream()
				.filter(scanner -> !scanner.isRan()).toList()));
	}

	/** Finalizes persistence/cleanup timing after the primary scan result has been stored. */
	public void finalizePerformance(long scanId, long totalMs, long persistenceMs,
			long cleanupMs, long completedAt) {
		Optional<PullRequestScanEntity> scan = scanRepo.findById(Long.valueOf(scanId));
		if (scan.isEmpty()) {
			return;
		}
		PullRequestScanEntity entity = scan.get();
		entity.setTotalDurationMs(Math.max(0, totalMs));
		entity.setPersistenceDurationMs(Math.max(0, persistenceMs));
		entity.setCleanupDurationMs(Math.max(0, cleanupMs));
		entity.setEndDate(completedAt);
		entity.setPerformanceComplete(true);
		scanRepo.saveAndFlush(entity);
		if (metricsProjectionWriter != null) {
			try {
				metricsProjectionWriter.recordPrPerformance(entity);
			} catch (RuntimeException e) {
				metricsProjectionWriter.recordFailure("pull_request_performance", e);
			}
		}
	}

	/**
	 * Determine if the Pull Request requires a Manual Code Review based on violation findings.
	 *
	 * @param violations the violations found in this scan
	 */
	public PullRequestMCRStatus resolveMCRStatus(List<PullRequestViolationEntity> violations) {
		for (PullRequestViolationEntity v : violations) {
			if (v.getViolationName().startsWith(MCR_NAME_PREFIX)) {
				return PullRequestMCRStatus.PENDING_REVIEW;
			}
		}

		return PullRequestMCRStatus.NOT_APPLICABLE;
	}

	/**
	 * Update the MCR status a Pull Request entity and all of its duplicates.
	 *
	 * @param id 			the id of the Pull Request scan entity to update
	 * @param mcrStatus 	the MCR status to update to
	 */
	public void updateMcrStatus(long id, PullRequestMCRStatus mcrStatus) {
		PullRequestScanEntity pr = scanRepo.findById(id);
		pr.setMcrStatus(mcrStatus);
		scanRepo.saveAndFlush(pr);
	}

	/**
	 * Given a {@linkplain PullRequest}, mark it as having been newly reviewed and now resolved.
	 * Every row for it is resolved: older data holds duplicates, and one left unresolved would
	 * keep the Pull Request open.
	 *
	 * @param pr the {@linkplain PullRequest} to resolve
	 */
	public void markPrResolved(PullRequest pr) {
		markPrResolved(pr, false);
	}

	/**
	 * Resolves the pull request and, when the SCM says it was merged or declined, records how
	 * and when, for the Merged/Declined chips and the merge gate view.
	 *
	 * @param pr          the {@linkplain PullRequest} to resolve
	 * @param scanPending whether a scan of it was queued or running when the close was seen
	 */
	public void markPrResolved(PullRequest pr, boolean scanPending) {
		long now = System.currentTimeMillis();

		List<PullRequestContainerEntity> prEntities = prRepo.findByApiLabelAndRepoNameAndPrId(
				pr.getApiLabel(), pr.getRepoName(), pr.getPrId());

		if (prEntities.isEmpty()) {
			LOG.error(
					"Request made to resolve a PR that hasn't been scanned yet (" + pr.getPRString()
							+ "). Creating and marking resolved anyway.");
			prEntities = List.of(new PullRequestContainerEntity(pr));
		}

		for (PullRequestContainerEntity prEntity : prEntities) {
			prEntity.setResolved(true);
			prEntity.setLastReviewedDate(now);
			recordClosed(prEntity, pr, now, scanPending);
			prRepo.saveAndFlush(prEntity);
		}
	}

	/** The SCM's update time is the close time; a payload without one falls back to now. */
	private static void recordClosed(PullRequestContainerEntity prEntity, PullRequest pr,
			long now, boolean scanPending) {
		prEntity.recordClosed(pr.getState(), pr.getUpdateTime() > 0 ? pr.getUpdateTime() : now,
				pr.getCommitHash(), scanPending);
	}


	/**
	 * Counts the number of repositories that have been scanned
	 *
	 * @return number of repositories scanned
	 */
	public long countRepos() {
		return repoRepo.count();
	}

	/**
	 * Counts the number of pull requests that have been scanned
	 *
	 * @return number of pull requests scanned
	 */
	public long countPrs() {
		return this.prRepo.count();
	}

	/**
	 * Gets the average byte size of the source scanned, across PR scans that have a recorded
	 * size (IMPROVEMENT_PLAN.md item 6.5). Scans from before item 6.3/6.4 landed, or whose
	 * size could not be measured, default to 0 and are excluded.
	 *
	 * @return the average source size in bytes, or 0 if no scan has a recorded size
	 */
	public double getAverageSourceSizeBytes() {
		Double average = scanRepo.findAverageSourceSizeBytes();
		return average == null ? 0.0 : average;
	}

	public PRScanPerformanceSummary getPerformanceSummarySince(long sinceMillis) {
		Object[] values = scanRepo.findPerformanceSummarySince(sinceMillis);
		if (values == null || values.length < 9) {
			return PRScanPerformanceSummary.empty();
		}
		return new PRScanPerformanceSummary(number(values[0]).longValue(),
				number(values[1]).doubleValue(), number(values[2]).doubleValue(),
				number(values[3]).doubleValue(), number(values[4]).doubleValue(),
				number(values[5]).doubleValue(), number(values[6]).doubleValue(),
				number(values[7]).doubleValue(), number(values[8]).doubleValue());
	}

	private Number number(Object value) {
		return value instanceof Number ? (Number) value : 0;
	}

	private PRScanResult generateScanResultForScan(PullRequestScanEntity scanEntity) {
		return generateScanResultForScan(scanEntity, new HashMap<>());
	}

	/**
	 * Same as {@link #generateScanResultForScan(PullRequestScanEntity)}, but takes a rule-name
	 * cache shared across every row of a results page instead of creating its own per-row. Rule
	 * names repeat heavily across scans (not just within one), and the cache-miss path
	 * ({@code ruleService.getRule(name)}) is an unindexed lookup, so resetting the cache every
	 * row re-pays that cost for names already resolved by an earlier row on the same page.
	 *
	 * @param scanEntity the scan to build a result for
	 * @param ruleCache  a rule-name cache shared across the whole page
	 * @return the mapped {@linkplain PRScanResult}
	 */
	private PRScanResult generateScanResultForScan(PullRequestScanEntity scanEntity,
			Map<String, RuleEntity> ruleCache) {
		PullRequestContainerEntity container = scanEntity.getContainer();
		String repo = container.getRepoName();
		String id = container.getPrId();

		// container.getScans() and scanEntity.getViolations() are @OneToMany(EAGER) - already
		// loaded by the time this method runs, so logging their size here is free and shows
		// how much unrelated data each row's implicit collection fetch pulled in.
		LOG.info(
				"generateScanResultForScan: scan={} violations={} container has {} scan(s) in history",
				scanEntity.getId(), scanEntity.getViolations().size(), container.getScans().size());

		long apiIntegrationStart = System.currentTimeMillis();
		AbstractScmIntegrationEntity entity =
				(AbstractScmIntegrationEntity) apiIntegrationService
						.findByLabel(container.getApiLabel());
		LOG.info("generateScanResultForScan: apiIntegrationService.findByLabel took {} ms",
				System.currentTimeMillis() - apiIntegrationStart);

		PRScanResult result = new PRScanResult();
		result.setId(scanEntity.getId());
        result.setProviderAssessments(scanEntity.getProviderAssessments());
		result.setClosedState(container.getClosedState());
		result.setResolved(container.isResolved());
		result.setDisplayName(repo + " #" + id);
		result.setAuthor(container.getAuthor());
		result.setDate(scanEntity.getEndDateMillis() > 0 ? scanEntity.getEndDate() : null);
		result.setStatusPresentation(StatusPresentationModel.fromScan(scanEntity));
		result.setPrLink(entity == null ? "" : entity.makePRLink(repo, id));
		result.setApiLabel(container.getApiLabel());
		result.setRepoName(repo);
		result.setPrId(id);
		result.setQueueWaitDurationMs(scanEntity.getQueueWaitDurationMs());
		result.setTotalDurationMs(scanEntity.getTotalDurationMs());
		result.setSourcePreparationDurationMs(scanEntity.getSourcePreparationDurationMs());
		result.setScannerExecutionDurationMs(scanEntity.getScannerExecutionDurationMs());
		result.setResultProcessingDurationMs(scanEntity.getResultProcessingDurationMs());
		result.setScmReportingDurationMs(scanEntity.getScmReportingDurationMs());
		result.setSourceSizeBytes(scanEntity.getSourceSizeBytes());
		result.setPersistenceDurationMs(scanEntity.getPersistenceDurationMs());
		result.setCleanupDurationMs(scanEntity.getCleanupDurationMs());
		result.setPerformanceComplete(scanEntity.isPerformanceComplete());
		result.setChangedFileCount(scanEntity.getChangedFileCount());
		result.setScanScope(scanEntity.getScanScope());
		result.setSourceStrategy(scanEntity.getSourceStrategy());
		result.setScannerTimings(PRScanTimings.readScanners(scanEntity.getScannerTimingsJson()));
		result.setExecutionSummary(new ScanExecutionSummary(scanEntity.getRulesEvaluated(),
				PRScanTimings.executions(scanEntity.getScannerTimingsJson(), scanEntity.getScannerExecutionsJson())));
		// One pass, with rule guidance looked up once per distinct rule name.
		//
		// This used to map the violation list twice - once for violations, once for MCR
		// findings - and generateResultForViolation issues a database query per
		// violation to fetch rule guidance. A scan with 416 violations therefore cost
		// 832 queries for a single row of the results page, which is what made
		// /scan/results/all time out at the load balancer. Rule names repeat heavily
		// within a scan, so caching by name collapses that to the number of distinct
		// rules - and ruleCache is now shared across the whole page (see the two-arg
		// overload above), so a name resolved by an earlier row isn't re-queried either.
		List<PRScanResultViolation> violations = new ArrayList<>();
		List<PRScanResultViolation> mcrFindings = new ArrayList<>();
		// Whether a rule was edited after this scan is asked once per rule, not once per finding.
		Map<String, RuleChange> ruleChanges = new HashMap<>();
		long scannedAtMillis = scanEntity.getEndDateMillis();
		for (PullRequestViolationEntity violation : scanEntity.getViolations()) {
			PRScanResultViolation mapped = generateResultForViolation(violation, ruleCache);
			String ruleName = violation.getViolationName();
			if (!ruleChanges.containsKey(ruleName)) {
				ruleChanges.put(ruleName,
						ruleChangeOf(ruleName, ruleCache.get(ruleName), scannedAtMillis));
			}
			mapped.setRuleChange(ruleChanges.get(ruleName));
			if (mapped.getViolationName().startsWith(MCR_NAME_PREFIX)) {
				mcrFindings.add(mapped);
			} else {
				violations.add(mapped);
			}
		}

		//Set violations, filter out MCR Findings, severity-first (Tier C backlog item)
		violations.sort(Comparator.comparingInt(PRScanResultViolation::getSeverityValue));
		result.setViolations(violations);

		//Set mcrStatus and mcrFindings, filter out other violations
		result.setMcrStatus(scanEntity.getMcrStatus());
		List<PRScanResultViolation> distinctMcrFindings =
				mcrFindings.stream().distinct().collect(Collectors.toList());
		distinctMcrFindings.sort(Comparator.comparingInt(PRScanResultViolation::getSeverityValue));
		result.setMcrFindings(distinctMcrFindings);

		return result;
	}

	/**
	 * Batch-fetches rule guidance for every distinct violation name across the given scans in a
	 * single query, instead of the one-query-per-name path in generateResultForViolation. Even
	 * with {@code rules.name} indexed, each individual lookup still pays a full DB round trip,
	 * and a page of scans can reference dozens of distinct names - this is what made
	 * /rest/scan/result/all and /scan/results/all slow even after the index landed.
	 *
	 * @param scans the scans that will be mapped for this page
	 * @return a rule-name cache pre-populated for every name referenced by {@code scans}; names
	 * with no matching rule are cached as {@code null}, matching
	 * generateResultForViolation's existing miss semantics
	 */
	private Map<String, RuleEntity> buildRuleCache(List<PullRequestScanEntity> scans) {
		Set<String> names = scans.stream()
				.flatMap(scan -> scan.getViolations().stream())
				.map(PullRequestViolationEntity::getViolationName)
				.collect(Collectors.toSet());
		Map<String, RuleEntity> cache = new HashMap<>();
		names.forEach(name -> cache.put(name, null));

		long start = System.currentTimeMillis();
		for (RuleEntity rule : ruleService.getRulesByNames(names)) {
			cache.put(rule.getName(), rule);
		}
		LOG.info(
				"buildRuleCache: batch-fetched {} distinct rule name(s) in {} ms ({} matched, {} not found)",
				names.size(), System.currentTimeMillis() - start,
				cache.values().stream().filter(Objects::nonNull).count(),
				cache.values().stream().filter(Objects::isNull).count());
		return cache;
	}

	/**
	 * What happened to a finding's rule after the scan ran. Matched-code-review findings have no
	 * rule row by design, so they are never reported as deleted.
	 */
	private RuleChange ruleChangeOf(String ruleName, RuleEntity rule, long scannedAtMillis) {
		if (ruleName.startsWith(MCR_NAME_PREFIX)) {
			return null;
		}
		if (rule == null) {
			return RuleChange.DELETED;
		}
		return ruleService.changedAfter(rule, scannedAtMillis) ? RuleChange.CHANGED : null;
	}

	private PRScanResultViolation generateResultForViolation(PullRequestViolationEntity violation,
			Map<String, RuleEntity> ruleCache) {
		PRScanResultViolation result = new PRScanResultViolation();
		result.setViolationId(violation.getId());
		result.setFileName(violation.getFileName());
		result.setLineNumber(violation.getLineNum());
		result.setSeverity(violation.getSeverity().getName());
		result.setSeverityValue(violation.getSeverity().getPriority());
		result.setViolationName(violation.getViolationName());
		var identity = violation.getRuleIdentity();
		if (identity != null) {
			result.setScannerModule(identity.module());
			result.setRuleId(identity.ruleId());
		}

		String message = "No guidance written for this rule yet.";
		// containsKey rather than computeIfAbsent: a violation whose rule no longer
		// exists resolves to null, and computeIfAbsent does not store nulls, so every
		// such violation would re-query. Caching the miss matters because MCR findings
		// routinely have no RuleEntity.
		String ruleName = violation.getViolationName();
		if (!ruleCache.containsKey(ruleName)) {
			long ruleLookupStart = System.currentTimeMillis();
			RuleEntity lookedUp = ruleService.getRule(ruleName);
			LOG.debug("generateResultForViolation: cache-miss ruleService.getRule({}) took {} ms",
					ruleName, System.currentTimeMillis() - ruleLookupStart);
			ruleCache.put(ruleName, lookedUp);
		}
		RuleEntity rule = ruleCache.get(ruleName);
		if (rule != null) {
			message = rule.getMessage();
			result.setExternalUrl(rule.getExternalUrl());
			if (result.getRuleId() == null) result.setRuleId(rule.getId());
		}
		result.setMessage(message);

		return result;
	}

	/**
	 * One page of the results page: the filter within the last
	 * {@value PRResultPeriod#RECENT_DAYS} days, or before them. Each window is read through an
	 * index on its date, so the page no longer sorts and counts every scan ever run.
	 *
	 * @param filter   the filter to divy-up the results
	 * @param period   the window
	 * @param pageSize the number of results to return
	 * @param pageNum  the pagenumber of results to return
	 * @return that page
	 */
	public PagedResult<PRScanResult> getScanResultsWithFilters(PRResultFilter filter,
			PRResultPeriod period, int pageSize, int pageNum) {
		long cutoff = PRResultPeriod.cutoff(System.currentTimeMillis());
		boolean recent = period == PRResultPeriod.RECENT;
		switch (filter) {
			case ALL:
			case VIOLATIONS: {
				PageRequest page = PageRequest.of(pageNum, pageSize,
						Sort.by(Direction.DESC, "endDate").and(Sort.by(Direction.DESC, "id")));
				Page<PullRequestScanEntity> scans = filter == PRResultFilter.ALL
						? (recent ? scanRepo.findEndedSince(cutoff, page)
								: scanRepo.findEndedBefore(cutoff, page))
						: (recent ? scanRepo.findWithFindingsEndedSince(cutoff, page)
								: scanRepo.findWithFindingsEndedBefore(cutoff, page));
				Map<String, RuleEntity> pageRuleCache = buildRuleCache(scans.getContent());
				return PagedResult.of(scans,
						scan -> generateScanResultForScan(scan, pageRuleCache));
			}
			case UNRESOLVED: {
				PageRequest page = PageRequest.of(pageNum, pageSize,
						Sort.by(Direction.DESC, "lastReviewedDate"));
				Page<PullRequestContainerEntity> unresolved = recent
						? prRepo.findByResolvedFalseAndLastReviewedDateGreaterThanEqual(cutoff, page)
						: prRepo.findByResolvedFalseAndLastReviewedDateBefore(cutoff, page);
				List<PullRequestScanEntity> latestScans = unresolved.getContent().stream()
						.map(container -> container.getScans().get(0))
						.collect(Collectors.toList());
				Map<String, RuleEntity> pageRuleCache = buildRuleCache(latestScans);
				return PagedResult.of(unresolved,
						container -> generateScanResultForScan(container.getScans().get(0),
								pageRuleCache));
			}
			default:
				throw new IllegalArgumentException("Filter is not configured to get PRs");
		}
	}

	/**
	 * Get a list of {@linkplain PRScanResult} based on the given filter and return the given page
	 * number's worth of data, over all time (the REST API's view)
	 *
	 * @param filter   the filter to divy-up the results
	 * @param pageSize the number of results to return
	 * @param pageNum  the pagenumber of results to return
	 * @return a list of size {@code pageSize} containing results using the {@code filter} on page
	 * {@code pageNum}
	 */
	public PagedResult<PRScanResult> getScanResultsWithFilters(PRResultFilter filter, int pageSize,
			int pageNum) {
		long overallStart = System.currentTimeMillis();
		switch (filter) {
			case ALL: {
				long findAllStart = System.currentTimeMillis();
				// findAll() itself is where the count query plus the two implicit
				// @OneToMany(EAGER) secondary SELECTs (violations, container.scans) happen -
				// timing it in isolation shows whether the cost is already here before any
				// per-row mapping in generateScanResultForScan runs.
				Page<PullRequestScanEntity> allScans = scanRepo.findAll(
						PageRequest.of(pageNum, pageSize, Sort.by(Direction.DESC, "endDate")));
				LOG.info("getScanResultsWithFilters(ALL): scanRepo.findAll took {} ms for {} row(s)",
						System.currentTimeMillis() - findAllStart, allScans.getNumberOfElements());
				Map<String, RuleEntity> pageRuleCache = buildRuleCache(allScans.getContent());
				PagedResult<PRScanResult> allResult = PagedResult.of(allScans,
						scan -> generateScanResultForScan(scan, pageRuleCache));
				LOG.info("getScanResultsWithFilters(ALL): total (findAll + mapping) took {} ms",
						System.currentTimeMillis() - overallStart);
				return allResult;
			}
			case UNRESOLVED: {
				Page<PullRequestContainerEntity> unresolved = prRepo.findByResolvedFalse(
						PageRequest.of(pageNum, pageSize,
								Sort.by(Direction.DESC, "lastReviewedDate")));
				// generateScanResultForScan only ever looks at container.getScans().get(0) for
				// this filter - build the cache from exactly that set, not every scan in each
				// container's history, so we're not fetching guidance nobody will read.
				List<PullRequestScanEntity> latestScans = unresolved.getContent().stream()
						.map(container -> container.getScans().get(0))
						.collect(Collectors.toList());
				Map<String, RuleEntity> pageRuleCache = buildRuleCache(latestScans);
				return PagedResult.of(unresolved,
						container -> generateScanResultForScan(container.getScans().get(0),
								pageRuleCache));
			}
			case VIOLATIONS: {
				Page<PullRequestScanEntity> violationScans = vioRepo.findAllNonMCRGroupByScan(
						PageRequest.of(pageNum, pageSize, Sort.by(Direction.DESC, "scan")));
				Map<String, RuleEntity> pageRuleCache = buildRuleCache(violationScans.getContent());
				return PagedResult.of(violationScans,
						scan -> generateScanResultForScan(scan, pageRuleCache));
			}
			default:
				LOG.error("Filter is not configured to get PRs");
				throw new IllegalArgumentException("Filter is not configured to get PRs");
		}
	}

	/**
	 * Get a list of {@linkplain PRScanResult} with MCRs based on the given filter and return the given page
	 * number's worth of data
	 *
	 * @param filter   the filter to divy-up the results
	 * @param pageSize the number of results to return
	 * @param pageNum  the pagenumber of results to return
	 * @return a list of size {@code pageSize} containing results using the {@code filter} on page
	 * {@code pageNum}
	 */
	public PagedResult<PRScanResult> getScanMCRsWithFilters(PullRequestMCRFilter filter,
			int pageSize, int pageNum) {
		switch (filter) {
			case ALL:
				return PagedResult.of(
						scanRepo.findLatestMcrsPerPR(PullRequestMCRStatus.NOT_APPLICABLE,
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "endDate"))),
						this::generateScanResultForScan);
			case PENDING:
				return PagedResult.of(
						scanRepo.findLatestMcrsPerPRByMcrStatus(PullRequestMCRStatus.PENDING_REVIEW,
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "endDate"))),
						this::generateScanResultForScan);
			case PROGRESS:
				return PagedResult.of(
						scanRepo.findLatestMcrsPerPRByMcrStatus(PullRequestMCRStatus.IN_PROGRESS,
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "endDate"))),
						this::generateScanResultForScan);
			case REVIEWED:
				return PagedResult.of(
						scanRepo.findLatestMcrsPerPRByMcrStatus(PullRequestMCRStatus.REVIEWED,
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "endDate"))),
						this::generateScanResultForScan);
			case RECOMMENDATIONS:
				return PagedResult.of(
						scanRepo.findLatestMcrsPerPRByMcrStatus(
								PullRequestMCRStatus.RECOMMENDATIONS,
								PageRequest.of(pageNum, pageSize,
										Sort.by(Direction.DESC, "endDate"))),
						this::generateScanResultForScan);
			default:
				LOG.error("Filter is not configured to get MCRs");
				throw new IllegalArgumentException("Filter is not configured to get MCRs");
		}
	}

	/**
	 * Get an individual result for a scan id
	 *
	 * @param scanId the id of the scan to get results for
	 * @return the result of the scan, or null if not found
	 */
	public PRScanResult getScanResultForScanId(String scanId) {
		Optional<PullRequestScanEntity> entity = scanRepo.findById(Long.valueOf(scanId));
		if (entity.isEmpty()) {
			return null;
		}
		// Same batching as getScanResultsWithFilters(ALL/VIOLATIONS) - a single scan can still
		// have hundreds of violations across many distinct rule names (see the 416/323-violation
		// examples already seen this session), so this must not fall back to the single-arg
		// overload's empty per-call cache.
		Map<String, RuleEntity> ruleCache = buildRuleCache(Collections.singletonList(entity.get()));
		PRScanResult result = generateScanResultForScan(entity.get(), ruleCache);
		attachCodeSnippets(entity.get(), result, sensitiveRuleNames(ruleCache));
		return result;
	}

	/**
	 * Populates the result's {@code codeFiles} with the source behind the findings, fetched from
	 * the SCM, so a reviewer can see the flagged code on this page instead of having to go find it
	 * in Bitbucket themselves. Only called from {@link #getScanResultForScanId(String)} -
	 * deliberately not from {@link #getScanResultsWithFilters}, which would fetch file content for
	 * every row of a list page and reintroduce the kind of per-row latency already fixed there.
	 * <p>
	 * There is one entry per <em>file that has findings</em>, not one per violation: each distinct
	 * file is fetched exactly once and its source rendered once, with every flagged line in it
	 * highlighted. Files the scan found nothing in are never fetched or listed, so the report's
	 * code section only ever shows files with issues.
	 *
	 * @param scanEntity         the scan the result was built from
	 * @param result             the already-built result to enrich in place
	 * @param sensitiveRuleNames names of the rules whose flagged lines must be masked
	 */
	private void attachCodeSnippets(PullRequestScanEntity scanEntity, PRScanResult result,
			Set<String> sensitiveRuleNames) {
		PullRequestContainerEntity container = scanEntity.getContainer();
		AbstractScmIntegrationEntity integration = (AbstractScmIntegrationEntity) apiIntegrationService
				.findByLabel(container.getApiLabel());
		java.util.function.Function<String, FileFetch> fetcher;
		if (integration == null) {
			// Still list the files, saying why there is no code, instead of an empty section
			FileFetch gone = FileFetch.unavailable("The source control integration \""
					+ container.getApiLabel() + "\" is no longer configured in Watchtower.");
			fetcher = file -> gone;
		} else {
			IScmApi api = (IScmApi) integration.createApi();
			PullRequest pullRequest = container.toPullRequest();
			String scanned = scanEntity.getCommitHash();
			fetcher = file -> scannedFileContent(api, pullRequest, container.getRepoName(), scanned,
					file);
		}

		// Kept as two separate lists/fields (codeFiles/mcrCodeFiles), not concatenated: each
		// report page's per-file finding count has to agree with that same page's findings table,
		// and the PR scan report and MCR report are two different pages/tables. Folding both
		// violation sets into one codeFiles list would make a file claim more findings than
		// whichever table was showing it.
		result.setCodeFiles(buildCodeFiles(result.getViolations(), sensitiveRuleNames, fetcher));
		result.setMcrCodeFiles(buildCodeFiles(result.getMcrFindings(), sensitiveRuleNames, fetcher));
	}

	/**
	 * The file as the scan saw it: read at the scan's commit, which stays readable after the pull
	 * request's branch is merged, deleted or pushed again. The branch is only the fallback, for a
	 * scan that recorded no commit or a commit the SCM would not serve; when both fail, the
	 * reason is the commit's, since that is the read that should have worked.
	 */
	private static FileFetch scannedFileContent(IScmApi api, PullRequest pullRequest,
			String repoName, String commitHash, String fileName) {
		FileFetch atCommit = commitHash == null || commitHash.isBlank()
				? FileFetch.unavailable("This scan did not record which commit it read, so the file"
						+ " cannot be fetched at that commit.")
				: api.fetchFileAtCommit(repoName, commitHash, fileName);
		if (atCommit != null && atCommit.isFound()) {
			return atCommit;
		}
		String onBranch = api.getFileContent(pullRequest, fileName);
		if (onBranch != null) {
			return FileFetch.found(onBranch);
		}
		return atCommit != null ? atCommit : FileFetch.unavailable(null);
	}

	/**
	 * Names of the rules whose module's scanner is sensitive (see
	 * {@link com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner#isSensitive()}).
	 * Resolved once per distinct rule rather than per finding. A finding whose rule no longer
	 * exists cannot be attributed to a module, so it is shown as before.
	 *
	 * @param ruleCache the scan's rules by name; a null value is a rule that was not found
	 * @return the sensitive rule names
	 */
	private Set<String> sensitiveRuleNames(Map<String, RuleEntity> ruleCache) {
		return ruleCache.values().stream()
				.filter(Objects::nonNull)
				.filter(rule -> {
					RuleDto dto = rule.toDto();
					return dto != null && scanRegistrationService.isSensitiveModule(dto.getModule());
				})
				.map(RuleEntity::getName)
				.collect(Collectors.toUnmodifiableSet());
	}

	/**
	 * Builds the code section entries for one list of findings: one entry per file that HAS a
	 * finding in that list, fetched from the SCM and rendered with every flagged line
	 * highlighted, so a reviewer can see the flagged code without leaving the report.
	 *
	 * @param findings           the findings to group by file and fetch source for
	 * @param sensitiveRuleNames names of the rules whose flagged lines must be masked
	 * @param fetcher            reads one file, with the reason when it cannot
	 * @return the code files to render, in stable alphabetical order by file name
	 */
	private List<PRScanResultFile> buildCodeFiles(List<PRScanResultViolation> findings,
			Set<String> sensitiveRuleNames, java.util.function.Function<String, FileFetch> fetcher) {
		// TreeMap, so the code section lists files in a stable alphabetical order instead of
		// whatever order the hash buckets happened to fall in. The null-file filter is what makes
		// that safe: TreeMap rejects a null key where the previous HashMap tolerated one, and a
		// finding with no file has no source to show anyway - it still appears in the findings
		// table above, just not in the code section.
		Map<String, List<PRScanResultViolation>> findingsByFile = findings.stream()
				.filter(finding -> finding.getFileName() != null)
				.collect(Collectors.groupingBy(PRScanResultViolation::getFileName, TreeMap::new,
						Collectors.toList()));

		Map<String, FileFetch> fetched = fetchAll(findingsByFile.keySet(), fetcher);
		List<PRScanResultFile> codeFiles = new ArrayList<>();
		for (Map.Entry<String, List<PRScanResultViolation>> entry : findingsByFile.entrySet()) {
			String fileName = entry.getKey();
			int findingCount = entry.getValue().size();
			// A file that could not be read is still listed with its finding count, and says why
			FileFetch fetch = fetched.get(fileName);
			Map<Boolean, Set<Integer>> linesBySensitivity = entry.getValue().stream()
					.collect(Collectors.partitioningBy(
							finding -> sensitiveRuleNames.contains(finding.getViolationName()),
							Collectors.mapping(PRScanResultViolation::getLineNumber,
									Collectors.toSet())));
			codeFiles.add(CodeExcerpts.of(fileName, fetch, linesBySensitivity.get(false),
					linesBySensitivity.get(true), findingCount));
		}
		return codeFiles;
	}

	/** How many files of one report are read from the source control server at once. */
	static final int FILE_FETCH_THREADS = 8;

	/**
	 * Reads every file once, several at a time: a report of 39 files read one after another took
	 * 16 seconds to open. The result keeps one entry per name; a read that fails says so.
	 */
	static Map<String, FileFetch> fetchAll(java.util.Collection<String> names,
			java.util.function.Function<String, FileFetch> fetcher) {
		Map<String, FileFetch> results = new java.util.LinkedHashMap<>();
		if (names.isEmpty()) {
			return results;
		}
		java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors
				.newFixedThreadPool(Math.min(FILE_FETCH_THREADS, names.size()));
		try {
			Map<String, java.util.concurrent.Future<FileFetch>> pending = new java.util.LinkedHashMap<>();
			names.forEach(name -> pending.put(name, pool.submit(() -> fetcher.apply(name))));
			for (var entry : pending.entrySet()) {
				try {
					FileFetch fetch = entry.getValue().get();
					results.put(entry.getKey(), fetch != null ? fetch : FileFetch.unavailable(null));
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					results.put(entry.getKey(), FileFetch.unavailable("The request was interrupted."));
				} catch (java.util.concurrent.ExecutionException e) {
					results.put(entry.getKey(), FileFetch.unavailable(null));
				}
			}
		} finally {
			pool.shutdownNow();
		}
		return results;
	}

	/**
	 * One finding's file for the Review finding page: fetched from the pull request's branch for
	 * this response only, the reviewed line highlighted, or masked when a sensitive (secrets)
	 * scanner flagged it. Empty when the scan, finding, integration or file is unavailable.
	 *
	 * @param scanId      the pull request scan
	 * @param violationId the reviewed finding (its review key)
	 * @return the code excerpt, or empty
	 */
	/** The reviewed finding's code and a link to that file in the pull request's diff (or null). */
	public record ReviewSource(PRScanResultFile file, String link) { }

	@org.springframework.transaction.annotation.Transactional(readOnly = true)
	public Optional<ReviewSource> reviewSource(long scanId, long violationId) {
		PullRequestScanEntity scan = scanRepo.findById(scanId);
		if (scan == null || scan.getViolations() == null) {
			return Optional.empty();
		}
		Optional<PullRequestViolationEntity> violation = scan.getViolations().stream()
				.filter(candidate -> candidate.getId() == violationId).findFirst();
		if (violation.isEmpty() || violation.get().getFileName() == null) {
			return Optional.empty();
		}
		PullRequestContainerEntity container = scan.getContainer();
		AbstractScmIntegrationEntity integration = (AbstractScmIntegrationEntity) apiIntegrationService
				.findByLabel(container.getApiLabel());
		String fileName = violation.get().getFileName();
		if (integration == null) {
			return Optional.of(new ReviewSource(PRScanResultFile.withoutSource(fileName, 1,
					"The source control integration \"" + container.getApiLabel()
							+ "\" is no longer configured in Watchtower."), null));
		}
		IScmApi api = (IScmApi) integration.createApi();
		FileFetch content = scannedFileContent(api, container.toPullRequest(), container.getRepoName(),
				scan.getCommitHash(), fileName);
		// Mask every line in this file that a secrets scanner flagged, whichever finding is being
		// reviewed - the same lines the report's code section masks.
		List<PullRequestViolationEntity> inFile = scan.getViolations().stream()
				.filter(candidate -> fileName.equals(candidate.getFileName())).toList();
		Map<String, RuleEntity> rules = new HashMap<>();
		ruleService.getRulesByNames(inFile.stream().map(PullRequestViolationEntity::getViolationName)
				.filter(Objects::nonNull).collect(Collectors.toSet()))
				.forEach(rule -> rules.putIfAbsent(rule.getName(), rule));
		Set<String> sensitiveRules = sensitiveRuleNames(rules);
		Set<Integer> masked = inFile.stream().filter(candidate -> sensitiveRules.contains(candidate.getViolationName()))
				.map(PullRequestViolationEntity::getLineNum).collect(Collectors.toUnmodifiableSet());
		int reviewed = violation.get().getLineNum();
		Set<Integer> plain = masked.contains(reviewed) ? Set.of() : Set.of(reviewed);
		String prLink = integration.makePRLink(container.getRepoName(), container.getPrId());
		String link = prLink == null || prLink.isBlank() ? null
				: prLink + "/diff#chg-" + org.springframework.web.util.UriUtils.encodePath(fileName,
						java.nio.charset.StandardCharsets.UTF_8);
		return Optional.of(new ReviewSource(CodeExcerpts.of(fileName, content, plain, masked, 1), link));
	}

	/**
	 * Shown in place of a line flagged by a sensitive scanner (see {@link CodeExcerpts}).
	 */
	static final String MASKED_LINE_TEXT = CodeExcerpts.MASKED_LINE_TEXT;

	/**
	 * Consolidate MCR findings so only one of the same finding per file
	 * is reported
	 *
	 * @param violations scan violations
	 */

	private void consolidateMCRFindings(List<PullRequestViolationEntity> violations) {
		//Pull all MCR findings
		List<PullRequestViolationEntity> mcrFindings = violations.stream()
				.filter(v -> v.getViolationName().startsWith("MCR Match: "))
				.collect(Collectors.toList());
		//Remove all MCR findings from violations
		mcrFindings.forEach(violations::remove);
		//Consolidate into distinct findings
		mcrFindings = mcrFindings.stream()
				.distinct()
				.collect(Collectors.toList());
		//Replace old findings with the consolidated per file findings
		violations.addAll(mcrFindings);
	}

	/**
	 * Get a pull request by label, repo, and id
	 *
	 * @param apiLabel the label of the api
	 * @param repo     the repository
	 * @param prid     the pull request id
	 * @return the pull request container, or null
	 */
	public PullRequestContainerEntity getPullRequestByLabelRepoAndId(String apiLabel, String repo,
			String prid) {
		return prRepo.findFirstByApiLabelAndRepoNameAndPrIdOrderByIdDesc(apiLabel, repo, prid);
	}

}
