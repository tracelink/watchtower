package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;

/**
 * Turns scanner output into a stored report while the repository is still on disk: reads each
 * flagged line only to fingerprint it, compares with the previous report of the branch for new
 * and fixed findings, and writes the report. The line text is hashed and discarded, never
 * written.
 *
 * @author Watchtower
 */
@Component
public class RepoScanReportWriter {

	private static final Logger LOG = LoggerFactory.getLogger(RepoScanReportWriter.class);

	/** Files larger than this are not read to fingerprint; the message is used instead. */
	static final long MAX_FINGERPRINT_FILE_BYTES = 5L * 1024 * 1024;

	private static final int MAX_FIXED = 1_000;

	private static final int MAX_ERRORS = 50;

	private static final int MAX_ERROR_LENGTH = 300;

	private final RepoReportStore store;
    @Autowired(required=false) private com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService remoteAssessments;
 @Autowired(required=false) private com.tracelink.appsec.watchtower.core.metrics.RuleMetricWriter ruleMetrics;

	private final int maxStoredFindings;

	@Autowired
	public RepoScanReportWriter(RepoReportStore store,
			@Value("${watchtower.reposcan.max-stored-findings:20000}") int maxStoredFindings) {
		this.store = store;
		this.maxStoredFindings = maxStoredFindings;
	}

	/**
	 * Builds, compares and stores the report of one scan.
	 *
	 * @param context    which scan this is
	 * @param reports    what the scanners returned
	 * @param workingDir the downloaded repository
	 * @param previous   the previous report of the branch, if any
	 * @return what was written, for the scan's summary row
	 * @throws IOException if the report could not be stored
	 */
	public WrittenReport write(ReportContext context, List<CodeScanReport> reports,
			Path workingDir, Optional<RepoScanReport> previous) throws IOException {
		// Apply the same snapshot bound as RDS before publishing an object.
		CodeScanExecutionSnapshotCodec.encode(context.executionSnapshot());
		Path root = workingDir.toAbsolutePath().normalize();
		List<RepoScanReport.Finding> all = findings(reports, root, context);
		var providers = remoteAssessments == null ? List.<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference>of() : remoteAssessments.reports("repository", context.scanId());
        var raw = new RepoScanReport(RepoScanReport.SCHEMA,context.scanId(),context.apiLabel(),context.repository(),context.branch(),context.commitHash(),context.rulesetName(),all,List.of(),errors(reports),all.size(),context.executionSnapshot(),null,providers,RepoScanReport.REPOSITORY_SCOPE,null);
        var eligibility = ScanComparison.assess(raw,previous.orElse(null));
        Set<String> before = eligibility.comparable() ? previous.orElseThrow().findings().stream()
            .map(RepoScanReport.Finding::fingerprint).collect(Collectors.toSet()) : null;
		List<RepoScanReport.Finding> marked = all.stream()
				.map(f -> before == null || before.contains(f.fingerprint()) ? f
						: f.withNew(true))
				.sorted(Comparator.comparingInt(RepoScanReportWriter::rank))
				.toList();
		List<RepoScanReport.Fixed> removed = eligibility.comparable() ? fixed(previous.orElseThrow(), all) : List.of();
        List<RepoScanReport.Fixed> fixed = removed.stream().limit(MAX_FIXED).toList();
        var comparison = new ScanComparison(eligibility.comparable(),eligibility.baselineScanId(),
            before == null ? null : (int)marked.stream().filter(RepoScanReport.Finding::isNew).count(),
            before == null ? null : removed.size(),removed.size()>MAX_FIXED,eligibility.reasons());
		List<RepoScanReport.Finding> kept =
				marked.size() > maxStoredFindings ? marked.subList(0, maxStoredFindings) : marked;

		RepoScanReport report = new RepoScanReport(RepoScanReport.SCHEMA, context.scanId(),
				context.apiLabel(), context.repository(), context.branch(), context.commitHash(),
				context.rulesetName(), kept, fixed, errors(reports), all.size(), context.executionSnapshot(),
    com.tracelink.appsec.watchtower.core.metrics.RuleMetricWriter.totals(all.stream().map(f ->
     new com.tracelink.appsec.watchtower.core.metrics.RuleMetricWriter.Count(f.ruleIdentity(),f.effectiveBlocking())).toList()),
                providers, RepoScanReport.REPOSITORY_SCOPE, comparison);
		String key = RepoReportStore.reportKey(context.apiLabel(), context.repository(),
				context.scanId());
		store.put(key, RepoReportCodec.encode(report), RepoReportCodec.CONTENT_TYPE);

  if (ruleMetrics != null) {
   try { ruleMetrics.recordRepository(context.scanId(), System.currentTimeMillis(), context.executionSnapshot(), all); }
   catch (RuntimeException e) { LOG.warn("Rule identity projection failed for repository scan {}", context.scanId()); }
  }

		List<RepoScanReport.Finding> added = marked.stream().filter(RepoScanReport.Finding::isNew)
				.toList();
		Map<String, Long> metricCounts = all.stream()
				.filter(f -> severity(f.severity()) != RulePriority.INFORMATIONAL)
				.collect(Collectors.groupingBy(RepoScanReport.Finding::rule, TreeMap::new,
						Collectors.counting()));
		return new WrittenReport(key,
				SeverityCounts.of(all.stream().map(f -> severity(f.severity())).toList()),
				ruleCounts(all), metricCounts, before == null ? null : added.size(),
				before == null ? null : removed.size(), added);
	}

	private List<RepoScanReport.Finding> findings(List<CodeScanReport> reports, Path root,
			ReportContext context) {
		Map<String, List<String>> lines = new HashMap<>();
		List<RepoScanReport.Finding> findings = new ArrayList<>();
		for (CodeScanReport report : reports) {
			for (CodeScanViolation violation : report.getViolations()) {
				// Manual-review matches belong to the pull request review flow, which counts them apart
				if (PullRequestViolationEntity.isMcrName(violation.getViolationName())) {
					continue;
				}
				String file = relative(root, violation.getFileName());
				boolean sensitive = context.sensitiveRules().contains(violation.getViolationName());
				// A secret is anchored on its rule message instead, so two findings of one
				// secrets rule in one file share an identity
				String lineText = sensitive ? null : line(lines, root, file, violation.getLineNum());
				RulePriority severity = violation.getSeverity() == null ? RulePriority.LOW
						: violation.getSeverity();
				findings.add(new RepoScanReport.Finding(violation.getViolationName(),
						severity.getName(), file, Math.max(0, violation.getLineNum()),
						violation.getMessage(),
						FindingFingerprint.of(violation.getViolationName(), file, lineText,
								violation.getMessage()),
						false, sensitive, violation.getRuleIdentity(), violation.getEngineFingerprint(),
						violation.getEffectiveBlocking(), RepoScanReport.createFindingKey(context.scanId(), findings.size())));
			}
		}
		return findings;
	}

	private static List<RepoScanReport.Fixed> fixed(RepoScanReport previous,
			List<RepoScanReport.Finding> current) {
		Set<String> now = current.stream().map(RepoScanReport.Finding::fingerprint)
				.collect(Collectors.toSet());
		return previous.findings().stream().filter(f -> !now.contains(f.fingerprint()))
				.map(f -> new RepoScanReport.Fixed(f.rule(), f.file(), f.message(),
						f.ruleIdentity(), f.engineFingerprint())).toList();
	}

	private static List<String> errors(List<CodeScanReport> reports) {
		return reports.stream().flatMap(r -> r.getErrors().stream())
				.map(CodeScanError::getErrorMessage).filter(StringUtils::isNotBlank)
				.map(message -> StringUtils.abbreviate(message, MAX_ERROR_LENGTH)).distinct()
				.limit(MAX_ERRORS).toList();
	}

	private static Map<String, Integer> ruleCounts(List<RepoScanReport.Finding> findings) {
		Map<String, Integer> counts = new TreeMap<>();
		findings.forEach(f -> counts.merge(f.rule(), 1, Integer::sum));
		return counts;
	}

	/**
	 * Reads one line to fingerprint it, keeping each file's lines for the rest of this scan only.
	 */
	private static String line(Map<String, List<String>> cache, Path root, String file,
			int lineNumber) {
		if (lineNumber <= 0) {
			return null;
		}
		List<String> fileLines = cache.computeIfAbsent(file, f -> read(root, f));
		return lineNumber <= fileLines.size() ? fileLines.get(lineNumber - 1) : null;
	}

	private static List<String> read(Path root, String file) {
		Path path = root.resolve(file).normalize();
		try {
			if (!path.startsWith(root) || !Files.isRegularFile(path)
					|| Files.size(path) > MAX_FINGERPRINT_FILE_BYTES) {
				return List.of();
			}
			return Files.readAllLines(path, StandardCharsets.UTF_8);
		} catch (MalformedInputException e) {
			return List.of();
		} catch (IOException e) {
			LOG.debug("Could not read {} to fingerprint findings", file);
			return List.of();
		}
	}

	/**
	 * @return the path relative to the repository root; scanners report absolute paths, some
	 *         relative ones
	 */
	static String relative(Path root, String fileName) {
		if (StringUtils.isBlank(fileName)) {
			return "";
		}
		Path path = Path.of(fileName);
		if (path.isAbsolute()) {
			Path normalized = path.normalize();
			return normalized.startsWith(root) ? root.relativize(normalized).toString()
					: String.valueOf(path.getFileName());
		}
		return path.normalize().toString();
	}

	private static int rank(RepoScanReport.Finding finding) {
		return severity(finding.severity()).getPriority();
	}

	private static RulePriority severity(String name) {
		RulePriority priority = RulePriority.priorityForName(name);
		return priority == null ? RulePriority.LOW : priority;
	}

	/**
	 * Identifies the scan a report belongs to.
	 *
	 * @param sensitiveRules rules whose findings are secrets: their fingerprints never hash the
	 *                       flagged line, since a hash of a short secret could be guessed back
	 */
	public record ReportContext(long scanId, String apiLabel, String repository, String branch,
			String commitHash, String rulesetName, Set<String> sensitiveRules,
			CodeScanExecutionSnapshot executionSnapshot) {

		public ReportContext(long scanId, String apiLabel, String repository, String branch,
				String commitHash, String rulesetName, Set<String> sensitiveRules) {
			this(scanId, apiLabel, repository, branch, commitHash, rulesetName, sensitiveRules, null);
		}

		public ReportContext withExecutionSnapshot(CodeScanExecutionSnapshot snapshot) {
			return new ReportContext(scanId, apiLabel, repository, branch, commitHash, rulesetName,
					sensitiveRules, snapshot);
		}

		public ReportContext {
			sensitiveRules = sensitiveRules == null ? Set.of() : Set.copyOf(sensitiveRules);
		}
	}

	/**
	 * What {@link #write} stored.
	 *
	 * @param reportKey   the report's key in the store
	 * @param counts      findings per severity, before any cap
	 * @param ruleCounts   findings per rule, before any cap
	 * @param metricCounts non-informational findings per rule, as the dashboards count them
	 * @param newCount     findings the previous scan did not have; null on a first scan
	 * @param fixedCount   previous findings now gone; null on a first scan
	 * @param newFindings  the new findings themselves, for alerts
	 */
	public record WrittenReport(String reportKey, SeverityCounts counts,
			Map<String, Integer> ruleCounts, Map<String, Long> metricCounts, Integer newCount,
			Integer fixedCount, List<RepoScanReport.Finding> newFindings) {
	}
}
