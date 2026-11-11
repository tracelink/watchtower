package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.scan;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.exception.RateLimitedException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionWriter;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmBranch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanOutcome;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.RepoScanRunner;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.WorkOutcome;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue.WorkerIdentity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoReportCodec;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoReportStore;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportWriter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportWriter.ReportContext;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportWriter.WrittenReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/**
 * Runs one queued repository scan: claims it, finds the branch head, skips the scan when the
 * head and ruleset are unchanged since the last scan, otherwise downloads and scans the
 * repository and stores the report. Every outcome is recorded on the scan's row.
 *
 * @author Watchtower
 */
@Service
public class DefaultRepoScanRunner implements RepoScanRunner {
	@Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService remoteAssessments;
	@org.springframework.beans.factory.annotation.Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.rule.candidate.RuleShadowService candidateShadow;


	private static final Logger LOG = LoggerFactory.getLogger(DefaultRepoScanRunner.class);

	private static final ObjectMapper MAPPER = new ObjectMapper();

	static final long STALE_AFTER_MILLIS = 3 * 60_000L;

	static final int MAX_ATTEMPTS = 3;

	private static final int RETRY_RUNNING_ELSEWHERE_SECONDS = 60;

	private static final int MAX_ERROR_LENGTH = 1_000;

	private final RepoScanRepository scans;

	private final RepoScanPlanRepository plans;

	private final ApiIntegrationService integrations;

	private final RulesetService rulesets;

	private final ScanRegistrationService registry;

	private final RepoReportStore store;

	private final RepoScanReportWriter writer;

	private final RepoCatalogDao catalog;

	private final MetricsProjectionWriter metrics;

	private final ApplicationEventPublisher events;

	private final WorkerIdentity worker;

	private final long maxRepoBytes;

	@Autowired
	public DefaultRepoScanRunner(RepoScanRepository scans, RepoScanPlanRepository plans,
			ApiIntegrationService integrations, RulesetService rulesets,
			ScanRegistrationService registry, RepoReportStore store, RepoScanReportWriter writer,
			RepoCatalogDao catalog, MetricsProjectionWriter metrics,
			ApplicationEventPublisher events, WorkerIdentity worker,
			@Value("${watchtower.reposcan.max-repo-size-mb:1024}") long maxRepoSizeMb) {
		this.scans = scans;
		this.plans = plans;
		this.integrations = integrations;
		this.rulesets = rulesets;
		this.registry = registry;
		this.store = store;
		this.writer = writer;
		this.catalog = catalog;
		this.metrics = metrics;
		this.events = events;
		this.worker = worker;
		this.maxRepoBytes = maxRepoSizeMb * 1024 * 1024;
	}

	@Override
	public WorkOutcome run(long scanId) {
		long now = System.currentTimeMillis();
		if (scans.claim(scanId, worker.id(), now, now - STALE_AFTER_MILLIS,
				ScanStatus.NOT_STARTED, ScanStatus.IN_PROGRESS) == 0) {
			return scans.findById(scanId).filter(s -> s.getStatus() == ScanStatus.IN_PROGRESS)
					.map(s -> WorkOutcome.retryLater(RETRY_RUNNING_ELSEWHERE_SECONDS))
					.orElse(WorkOutcome.done());
		}
		RepoScanEntity scan = scans.findWithRepository(scanId).orElse(null);
		if (scan == null) {
			return WorkOutcome.done();
		}
		try {
			return execute(scan);
		} catch (RateLimitedException e) {
			LOG.info("Repository scan {} rate limited; retrying in {}s", scanId,
					e.getRetryAfterSeconds());
			scan.setStatus(ScanStatus.NOT_STARTED);
			scans.save(scan);
			return WorkOutcome.retryLater(e.getRetryAfterSeconds());
		} catch (RuntimeException e) {
			if (interrupted(e)) return retryAfterInterruption(scan);
			LOG.error("Repository scan " + scanId + " failed", e);
			return fail(scan, describe(e));
		}
	}

	private WorkOutcome execute(RepoScanEntity scan) {
		if (scan.getAttempts() > MAX_ATTEMPTS && (remoteAssessments == null || remoteAssessments.repositoryContext(scan.getId()).isEmpty())) {
			return fail(scan, "Stopped after " + MAX_ATTEMPTS + " attempts");
		}
		RepositoryEntity repo = scan.getRepository();
		IScmApi api = api(repo.getApiLabel());
		if (api == null) {
			return fail(scan, "Integration " + repo.getApiLabel() + " is not configured");
		}
		RulesetEntity ruleset = ruleset(scan, repo);
		if (ruleset == null) {
			return fail(scan, "No ruleset to scan with");
		}
		if (registry.getCodeScanners().isEmpty()) {
			return fail(scan, "No code scanners are installed");
		}
		RulesetDto rules = ruleset.toDto();
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(rules);
		config.setRepositoryName(repo.getRepoName());
		config.setThreads(0); // RepoScanAgent uses the same execution settings.
		CodeScanExecutionSnapshot preview = CodeScanExecutionSnapshot.capture(rules,
				registry.getCodeScanners(), config);
		scan.setRulesetName(ruleset.getName());
		scan.setRulesetFingerprint(preview.fingerprint());
		var resumed = remoteAssessments == null ? Optional.<com.tracelink.appsec.watchtower.core.scan.code.ScanExecutionContext>empty()
				: remoteAssessments.repositoryContext(scan.getId());
		Optional<ScmBranch> head = resumed.isPresent() ? Optional.of(new ScmBranch(scan.getBranch(), resumed.get().commit(), scan.getCommitDate()))
				: api.getBranch(repo.getRepoName(), scan.getBranch());
		if (head.isEmpty()) {
			return finish(scan, RepoScanOutcome.BRANCH_MISSING);
		}
		scan.setCommitHash(head.get().commitHash());
		scan.setCommitDate(head.get().commitDate());
		scans.saveAndFlush(scan); // Pin before remote enlistment and source export.
		if (maxRepoBytes > 0 && repo.getSizeBytes() > maxRepoBytes) {
			return finish(scan, RepoScanOutcome.SKIPPED_SIZE);
		}
		Optional<RepoScanEntity> previous = scans
				.findFirstByRepositoryIdAndBranchAndStatusAndIdNotOrderByEndDateDesc(repo.getId(),
						scan.getBranch(), ScanStatus.DONE, scan.getId())
				.filter(p -> p.getReportKey() != null);
		if (preview.isReusable() && previous.isPresent() && isUnchanged(previous.get(), scan)
				&& reuse(previous.get(), scan, preview, config)) {
			return finish(scan, RepoScanOutcome.UNCHANGED);
		}
		return scan(scan, repo, api, rules, previous);
	}

	private WorkOutcome scan(RepoScanEntity scan, RepositoryEntity repo, IScmApi api,
			RulesetDto rules, Optional<RepoScanEntity> previous) {
		boolean remoteSelected = remoteAssessments != null && (remoteAssessments.selected(rules) || remoteAssessments.repositoryContext(scan.getId()).isPresent());
		String remoteRun = remoteSelected ? remoteAssessments.prepareRepository(
				new com.tracelink.appsec.watchtower.core.scan.code.ScanExecutionContext("repository-" + scan.getId(), CodeScanType.REPOSITORY,
						scan.getId(), repo.getId(), repo.getApiLabel(), repo.getRepoName(), scan.getBranch(), scan.getCommitHash(), null, null, null, null), rules) : null;
		Optional<RepoScanReport> previousReport = previous.flatMap(this::load);
		ReportContext context = new ReportContext(scan.getId(), repo.getApiLabel(),
				repo.getRepoName(), scan.getBranch(), scan.getCommitHash(), rules.getName(),
				rules.getAllRules().stream().filter(r -> registry.isSensitiveModule(r.getModule()))
						.map(RuleDto::getName).collect(Collectors.toSet()));
		AtomicReference<WrittenReport> written = new AtomicReference<>();
		AtomicReference<ScanExecutionSummary> summary = new AtomicReference<>();
		RepoScanAgent agent = new RepoScanAgent(scan.getId(), api, repo.getRepoName(),
				scan.getCommitHash(), (reports, workingDir, executions) -> {
					written.set(writer.write(context.withExecutionSnapshot(executions.codeSnapshot()),
							reports, workingDir, previousReport));
					summary.set(executions);
				}).withCandidateShadow(candidateShadow).withScanners(registry.getCodeScanners().stream()
						.filter(s -> s.getExecutionCapability() != com.tracelink.appsec.watchtower.core.module.scanner.ExecutionCapability.REMOTE_SERVICE).toList()).withRuleset(rules);
		agent.run();
			// The AWS child has its own durable queue and does not hold this local scan worker.
		if (interrupted(agent.getFailure())) return retryAfterInterruption(scan);
		scan.setExecutionSnapshotJson(CodeScanExecutionSnapshotCodec.encode(agent.executionSummary().codeSnapshot()));
		scan.setScannerExecutionsJson(ScanExecutionSummaryCodec.encode(agent.executionSummary().scanners()));
		if (agent.hasFailed() || written.get() == null) {
			if (remoteRun != null) remoteAssessments.cancelRepository(remoteRun);
			Exception failure = agent.getFailure();
			if (failure instanceof RateLimitedException rateLimited) {
				throw rateLimited;
			}
			return fail(scan, failure == null ? "The scan produced no report" : describe(failure));
		}
		WrittenReport report = written.get();
		scan.setReportKey(report.reportKey());
		scan.setSeverityCounts(report.counts());
        scan.setProviderSummaryJson(com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference.encode(
            remoteAssessments == null ? List.of() : remoteAssessments.reports("repository", scan.getId())));
		scan.setRuleCounts(json(report.ruleCounts()));
		scan.setNewCount(report.newCount());
		scan.setFixedCount(report.fixedCount());
		if (summary.get() != null) {
			scan.setRulesEvaluated(summary.get().rulesEvaluated());
			scan.setScannerExecutionsJson(
					ScanExecutionSummaryCodec.encode(summary.get().scanners()));
			scan.setExecutionSnapshotJson(CodeScanExecutionSnapshotCodec.encode(summary.get().codeSnapshot()));
			if (summary.get().codeSnapshot() != null)
				scan.setRulesetFingerprint(summary.get().codeSnapshot().fingerprint());
		}
		WorkOutcome outcome = finish(scan, RepoScanOutcome.SCANNED);
		recordMetrics(scan, report);
		events.publishEvent(new RepoScanCompletedEvent(scan.getId(), repo.getApiLabel(),
				repo.getRepoName(), scan.getBranch(), scan.getCommitHash(),
				report.newCount() == null, report.newFindings()));
		return outcome;
	}

	private boolean isUnchanged(RepoScanEntity previous, RepoScanEntity scan) {
		return StringUtils.equals(previous.getCommitHash(), scan.getCommitHash())
				&& StringUtils.equals(previous.getRulesetFingerprint(),
						scan.getRulesetFingerprint());
	}

	/**
	 * Writes a new envelope with explicit reuse provenance and distinct finding occurrences.
	 * Legacy, partial, or incompletely identified executions must be scanned again.
	 */
	private boolean reuse(RepoScanEntity previous, RepoScanEntity scan, CodeScanExecutionSnapshot preview, CodeScanConfig config) {
  if(!preview.fingerprint().equals(CodeScanExecutionSnapshot.capture(config.getRuleset(),registry.getCodeScanners(),config).fingerprint()))return false;
		Optional<RepoScanReport> loaded = load(previous);
		if (loaded.isEmpty()) return false;
		RepoScanReport report = loaded.get();
		CodeScanExecutionSnapshot original = report.executionSnapshot();
		if (report.schema() != RepoScanReport.SCHEMA || original == null
				|| !RepoScanReport.REPOSITORY_SCOPE.equals(report.scope()) || !report.providerAssessments().isEmpty()
                || !original.hasSuccessfulExecution() || !report.scannerErrors().isEmpty() || report.isTruncated()
				|| report.scanId() != previous.getId()
				|| !StringUtils.equals(report.apiLabel(), scan.getRepository().getApiLabel())
				|| !StringUtils.equals(report.repository(), scan.getRepository().getRepoName())
				|| !StringUtils.equals(report.branch(), scan.getBranch())
				|| !StringUtils.equals(report.commitHash(), scan.getCommitHash())
				|| !StringUtils.equals(original.fingerprint(), preview.fingerprint())
				|| report.findings().stream().anyMatch(finding -> finding.ruleIdentity() == null
						|| original.rules().stream().noneMatch(rule -> rule.identity().equals(finding.ruleIdentity())
								&& StringUtils.equals(rule.name(), finding.rule())
								&& StringUtils.equals(original.engineKey(rule.scanner()), finding.engineFingerprint())))) return false;
		CodeScanExecutionSnapshot reused = original.reusedFrom(previous.getId());
		String snapshotJson = CodeScanExecutionSnapshotCodec.encode(reused);
		List<RepoScanReport.Finding> findings = java.util.stream.IntStream.range(0, report.findings().size())
				.mapToObj(i -> report.findings().get(i).reusedIn(scan.getId(), i)).toList();
		RepoScanReport copy = new RepoScanReport(RepoScanReport.SCHEMA, scan.getId(), report.apiLabel(),
				report.repository(), report.branch(), report.commitHash(), report.rulesetName(), findings,
				List.of(), List.of(), report.totalFindings(), reused).withComparison(RepoScanReport.REPOSITORY_SCOPE,
                    new com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.ScanComparison(true,previous.getId(),0,0,false,List.of()));
		String key = RepoReportStore.reportKey(scan.getRepository().getApiLabel(),
				scan.getRepository().getRepoName(), scan.getId());
		try {
			store.put(key, RepoReportCodec.encode(copy), RepoReportCodec.CONTENT_TYPE);
		} catch (IOException e) {
			LOG.warn("Could not reuse the report of scan " + previous.getId() + "; rescanning",
					e);
			return false;
		}
		if(!preview.fingerprint().equals(CodeScanExecutionSnapshot.capture(config.getRuleset(),registry.getCodeScanners(),config).fingerprint()))return false;
  scan.setReportKey(key);
		scan.setSeverityCounts(previous.getSeverityCounts());
		scan.setRuleCounts(previous.getRuleCounts());
		scan.setNewCount(0);
		scan.setFixedCount(0);
		scan.setRulesEvaluated(0);
		scan.setExecutionSnapshotJson(snapshotJson);
		scan.setScannerExecutionsJson(ScanExecutionSummaryCodec.encode(original.engines().stream()
				.map(engine -> new ScanExecutionSummary.ScannerExecution(engine.scanner(), "REUSED", 0,
						"Report reused from scan " + previous.getId())).toList()));
		return true;
	}

	private Optional<RepoScanReport> load(RepoScanEntity previous) {
		try {
			return store.get(previous.getReportKey()).map(bytes -> {
				try {
					return RepoReportCodec.decode(bytes);
				} catch (IOException e) {
					LOG.warn("Unreadable report for scan {}", previous.getId());
					return null;
				}
			});
		} catch (IOException e) {
			LOG.warn("Could not read the report of scan " + previous.getId(), e);
			return Optional.empty();
		}
	}

	private WorkOutcome finish(RepoScanEntity scan, RepoScanOutcome outcome) {
		scan.setOutcome(outcome);
		scan.setStatus(ScanStatus.DONE);
		scan.setEndDate(System.currentTimeMillis());
		scans.save(scan);
		if (scan.getReportKey() != null) {
			catalog.setLastScan(scan.getRepository().getId(), scan.getId());
		}
		LOG.info("Repository scan {} of {}@{}: {}", scan.getId(),
				scan.getRepository().getRepoName(), scan.getBranch(), outcome.getDisplayName());
		return WorkOutcome.done();
	}

	private WorkOutcome fail(RepoScanEntity scan, String error) {
		scan.setStatus(ScanStatus.FAILED);
		scan.setError(StringUtils.abbreviate(error, MAX_ERROR_LENGTH));
		scan.setEndDate(System.currentTimeMillis());
		scans.save(scan);
		return WorkOutcome.done();
	}

	private boolean interrupted(Throwable failure) {
		if (Thread.currentThread().isInterrupted()) return true;
		for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
			if (cause instanceof InterruptedException) return true;
		}
		return false;
	}

	private WorkOutcome retryAfterInterruption(RepoScanEntity scan) {
		Thread.currentThread().interrupt();
		LOG.info("Repository scan {} interrupted; leaving saved work for recovery", scan.getId());
		return WorkOutcome.retryLater(RETRY_RUNNING_ELSEWHERE_SECONDS);
	}

	private void recordMetrics(RepoScanEntity scan, WrittenReport report) {
		try {
			metrics.recordSummary(CodeScanType.REPOSITORY.getTypeName(), scan.getId(),
					scan.getStartDate(), scan.getEndDate(), report.metricCounts(), 0);
		} catch (RuntimeException e) {
			LOG.warn("Could not record metrics for repository scan " + scan.getId(), e);
		}
	}

	private IScmApi api(String apiLabel) {
		ApiIntegrationEntity integration = integrations.findByLabel(apiLabel);
		return integration != null && integration.createApi() instanceof IScmApi api ? api : null;
	}

	/**
	 * @return the plan's ruleset, else the repository's own, else the default
	 */
	private RulesetEntity ruleset(RepoScanEntity scan, RepositoryEntity repo) {
		Long planRuleset = plans.findById(scan.getPlanId()).map(p -> p.getRulesetId())
				.orElse(null);
		if (planRuleset != null) {
			try {
				return rulesets.getRuleset(planRuleset);
			} catch (RulesetNotFoundException e) {
				LOG.info("Ruleset {} of plan {} is gone; using the repository's", planRuleset,
						scan.getPlanId());
			}
		}
		return repo.getRuleset() != null ? repo.getRuleset() : rulesets.getDefaultRuleset();
	}

	private static String json(Object value) {
		try {
			return MAPPER.writeValueAsString(value);
		} catch (JsonProcessingException e) {
			return "{}";
		}
	}

	private static String describe(Exception e) {
		Throwable root = e.getCause() != null && StringUtils.isBlank(e.getMessage())
				? e.getCause() : e;
		return StringUtils.defaultIfBlank(root.getMessage(), root.getClass().getSimpleName());
	}
}
