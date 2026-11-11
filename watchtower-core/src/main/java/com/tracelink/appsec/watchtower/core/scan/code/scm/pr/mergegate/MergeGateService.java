package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.AbstractScmIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PullRequestBypassRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PullRequestBypassRepository.BypassWindow;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateClassifier.Bypass;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateClassifier.MergedPullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateClassifier.Scan;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateReport.BeforeScan;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateReport.Blocking;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateReport.MergedPullRequestRow;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateReport.RepositoryCount;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository.ClosedPullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository.GateScan;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;

/**
 * Counts the merges Watchtower had not finished scanning, or whose scan blocked, so an
 * administrator can see what enforcing a merge gate would change. Reads only rows the merges and
 * scans already wrote: no job, no state of its own.
 *
 * @author Watchtower
 */
@Service
public class MergeGateService {
	/** The longest window, in days. */
	public static final int MAX_DAYS = 90;
	/** The window the page opens on, in days. */
	public static final int DEFAULT_DAYS = 30;
	/** Merges read per window; past this the report says it is truncated. */
	static final int MAX_MERGES = 10_000;
	/**
	 * How long a report is reused. Each one reads every merge in its window and their scans; a
	 * refreshed page or a polling script must not repeat that against the database each time.
	 */
	static final Duration CACHE_TTL = Duration.ofSeconds(60);
	/** Merges listed; the counts still cover every merge read. */
	static final int MAX_ROWS = 500;
	static final int TOP_REPOSITORIES = 10;
	/** Ids per IN list, under every database's bind limit. */
	private static final int BATCH = 1_000;

	private final PRContainerRepository pullRequests;
	private final PRScanRepository scans;
	private final PRViolationRepository violations;
	private final PullRequestBypassRepository bypasses;
	private final ApiIntegrationService integrations;
	private final Clock clock;
	/** Per window, on this pod: a minute-old figure is fine for a trend view. */
	private final Map<Integer, Cached> cache = new ConcurrentHashMap<>();

	@Autowired
	public MergeGateService(PRContainerRepository pullRequests, PRScanRepository scans,
			PRViolationRepository violations, PullRequestBypassRepository bypasses,
			ApiIntegrationService integrations) {
		this(pullRequests, scans, violations, bypasses, integrations, Clock.systemUTC());
	}

	MergeGateService(PRContainerRepository pullRequests, PRScanRepository scans,
			PRViolationRepository violations, PullRequestBypassRepository bypasses,
			ApiIntegrationService integrations, Clock clock) {
		this.pullRequests = pullRequests;
		this.scans = scans;
		this.violations = violations;
		this.bypasses = bypasses;
		this.integrations = integrations;
		this.clock = clock;
	}

	/** One merged pull request, its duplicate rows folded together. */
	private record Merge(String apiLabel, String repoName, String prId, List<Long> containerIds,
			MergedPullRequest merged) {
	}

	/** A merge and what Watchtower knew when it happened. */
	private record Classified(Merge merge, MergeGateOutcome outcome) {
	}

	/** A report and when it was built, epoch millis. */
	private record Cached(long builtAt, MergeGateReport report) {
	}

	/**
	 * @param days the window, 1 to {@value #MAX_DAYS}
	 * @return the window's merges by what Watchtower knew when each happened
	 * @throws IllegalArgumentException if the window is out of range
	 */
	@Transactional(readOnly = true)
	public MergeGateReport report(int days) {
		if (days < 1 || days > MAX_DAYS) {
			throw new IllegalArgumentException(
					"Choose a window of 1 to " + MAX_DAYS + " days.");
		}
		long now = clock.millis();
		Cached cached = cache.get(days);
		if (cached != null && now - cached.builtAt() < CACHE_TTL.toMillis()) {
			return cached.report();
		}
		MergeGateReport report = build(days, now);
		cache.put(days, new Cached(now, report));
		return report;
	}

	private MergeGateReport build(int days, long now) {
		long since = now - Duration.ofDays(days).toMillis();
		List<ClosedPullRequest> rows = pullRequests.findClosedSince(PullRequestState.MERGED,
				since, PageRequest.of(0, MAX_MERGES + 1));
		boolean truncated = rows.size() > MAX_MERGES;
		List<Merge> merges = fold(truncated ? rows.subList(0, MAX_MERGES) : rows);
		List<Classified> classified = classify(merges, since);
		return summarize(days, since, classified, truncated);
	}

	/**
	 * Older data holds duplicate rows for one pull request, and names compare without case in
	 * MySQL, so rows are folded by a case-blind key. The earliest close is the merge.
	 */
	private static List<Merge> fold(List<ClosedPullRequest> rows) {
		Map<String, List<ClosedPullRequest>> byPullRequest = new LinkedHashMap<>();
		for (ClosedPullRequest row : rows) {
			byPullRequest.computeIfAbsent(key(row.getApiLabel(), row.getRepoName(), row.getPrId()),
					k -> new ArrayList<>()).add(row);
		}
		List<Merge> merges = new ArrayList<>();
		for (List<ClosedPullRequest> copies : byPullRequest.values()) {
			ClosedPullRequest first = copies.stream()
					.min(Comparator.comparingLong(ClosedPullRequest::getClosedAt)).orElseThrow();
			boolean pending = copies.stream()
					.anyMatch(c -> Boolean.TRUE.equals(c.getScanPendingAtClose()));
			merges.add(new Merge(first.getApiLabel(), first.getRepoName(), first.getPrId(),
					copies.stream().map(ClosedPullRequest::getId).toList(),
					new MergedPullRequest(first.getClosedAt(), first.getMergedCommit(), pending)));
		}
		return merges;
	}

	private List<Classified> classify(List<Merge> merges, long since) {
		Map<Long, List<Scan>> scansByContainer = scansByContainer(merges);
		Map<String, List<Bypass>> bypassesByPullRequest = bypassesByPullRequest(since);
		Function<Merge, List<Scan>> scansOf = merge -> merge.containerIds().stream()
				.flatMap(id -> scansByContainer.getOrDefault(id, List.of()).stream()).toList();
		Set<Long> bypassedWhenFound = bypassedWhenFound(merges, scansOf);
		return merges.stream().map(merge -> new Classified(merge, MergeGateClassifier.classify(
				merge.merged(), scansOf.apply(merge),
				bypassesByPullRequest.getOrDefault(
						key(merge.apiLabel(), merge.repoName(), merge.prId()), List.of()),
				bypassedWhenFound))).toList();
	}

	private Map<Long, List<Scan>> scansByContainer(List<Merge> merges) {
		List<Long> ids = merges.stream().flatMap(m -> m.containerIds().stream()).toList();
		Map<Long, List<Scan>> byContainer = new HashMap<>();
		for (List<Long> batch : batches(ids)) {
			for (GateScan s : scans.findGateScansByContainerIds(batch)) {
				byContainer.computeIfAbsent(s.getContainerId(), k -> new ArrayList<>())
						.add(new Scan(s.getScanId(), s.getCommitHash(), s.getStatus(),
								s.getEndDate(), s.isBlocked()));
			}
		}
		return byContainer;
	}

	/** Only scans that would gate a merge and did not block need their findings read. */
	private Set<Long> bypassedWhenFound(List<Merge> merges, Function<Merge, List<Scan>> scansOf) {
		List<Long> unblocked = merges.stream()
				.flatMap(m -> MergeGateClassifier.gatingScan(m.merged(), scansOf.apply(m)).stream())
				.filter(s -> !s.blocked()).map(Scan::scanId).toList();
		Set<Long> bypassed = new HashSet<>();
		for (List<Long> batch : batches(unblocked)) {
			bypassed.addAll(violations.findScanIdsWithBypassedFindings(batch));
		}
		return bypassed;
	}

	private Map<String, List<Bypass>> bypassesByPullRequest(long since) {
		Map<String, List<Bypass>> byPullRequest = new HashMap<>();
		for (BypassWindow b : bypasses.findWindowsSince(since)) {
			byPullRequest.computeIfAbsent(key(b.getApiLabel(), b.getRepoName(), b.getPrId()),
					k -> new ArrayList<>()).add(new Bypass(b.getCreatedAt(), b.getRevokedAt()));
		}
		return byPullRequest;
	}

	private MergeGateReport summarize(int days, long since, List<Classified> classified,
			boolean truncated) {
		Map<MergeGateOutcome, Integer> counts = new EnumMap<>(MergeGateOutcome.class);
		classified.forEach(c -> counts.merge(c.outcome(), 1, Integer::sum));
		Function<MergeGateOutcome, Integer> count = outcome -> counts.getOrDefault(outcome, 0);
		BeforeScan beforeScan = new BeforeScan(
				count.apply(MergeGateOutcome.SCAN_IN_PROGRESS)
						+ count.apply(MergeGateOutcome.NEWER_COMMIT_NOT_SCANNED)
						+ count.apply(MergeGateOutcome.SCAN_FAILED)
						+ count.apply(MergeGateOutcome.NEVER_SCANNED),
				count.apply(MergeGateOutcome.SCAN_IN_PROGRESS),
				count.apply(MergeGateOutcome.NEWER_COMMIT_NOT_SCANNED),
				count.apply(MergeGateOutcome.SCAN_FAILED),
				count.apply(MergeGateOutcome.NEVER_SCANNED));
		Blocking blocking = new Blocking(
				count.apply(MergeGateOutcome.BLOCKED_BYPASSED)
						+ count.apply(MergeGateOutcome.BLOCKED_UNBYPASSED),
				count.apply(MergeGateOutcome.BLOCKED_BYPASSED),
				count.apply(MergeGateOutcome.BLOCKED_UNBYPASSED));
		return new MergeGateReport(days, since, classified.size(),
				count.apply(MergeGateOutcome.SCANNED_CLEAN), beforeScan, blocking,
				topRepositories(classified), rows(classified), truncated);
	}

	private static List<RepositoryCount> topRepositories(List<Classified> classified) {
		Map<String, int[]> counts = new LinkedHashMap<>();
		Map<String, Merge> names = new HashMap<>();
		for (Classified c : classified) {
			String key = key(c.merge().apiLabel(), c.merge().repoName(), "");
			names.putIfAbsent(key, c.merge());
			int[] n = counts.computeIfAbsent(key, k -> new int[3]);
			n[0]++;
			if (c.outcome().getKind() == MergeGateOutcome.Kind.BEFORE_SCAN) {
				n[1]++;
			} else if (c.outcome() == MergeGateOutcome.BLOCKED_UNBYPASSED) {
				n[2]++;
			}
		}
		return counts.entrySet().stream()
				.map(e -> new RepositoryCount(names.get(e.getKey()).apiLabel(),
						names.get(e.getKey()).repoName(), e.getValue()[0], e.getValue()[1],
						e.getValue()[2], e.getValue()[1] + e.getValue()[2]))
				.filter(r -> r.ungated() > 0)
				.sorted(Comparator.comparingInt(RepositoryCount::ungated).reversed()
						.thenComparing(Comparator.comparingInt(RepositoryCount::merges).reversed())
						.thenComparing(RepositoryCount::repository))
				.limit(TOP_REPOSITORIES).toList();
	}

	private List<MergedPullRequestRow> rows(List<Classified> classified) {
		Map<String, AbstractScmIntegrationEntity> scmByLabel = new HashMap<>();
		return classified.stream()
				.filter(c -> c.outcome() != MergeGateOutcome.SCANNED_CLEAN)
				.sorted(Comparator.comparingLong((Classified c) -> c.merge().merged().mergedAt())
						.reversed())
				.limit(MAX_ROWS)
				.map(c -> {
					Merge m = c.merge();
					AbstractScmIntegrationEntity scm = scmByLabel.computeIfAbsent(m.apiLabel(),
							label -> integrations.findByLabel(label)
									instanceof AbstractScmIntegrationEntity e ? e : null);
					return new MergedPullRequestRow(m.apiLabel(), m.repoName(), m.prId(),
							scm == null ? null : scm.makePRLink(m.repoName(), m.prId()),
							m.merged().mergedAt(), m.merged().mergedCommit(), c.outcome(),
							c.outcome().getLabel());
				}).toList();
	}

	private static String key(String apiLabel, String repoName, String prId) {
		return (apiLabel + "\u0000" + repoName + "\u0000" + prId).toLowerCase(Locale.ROOT);
	}

	private static List<List<Long>> batches(Collection<Long> ids) {
		List<Long> all = List.copyOf(ids);
		List<List<Long>> batches = new ArrayList<>();
		for (int i = 0; i < all.size(); i += BATCH) {
			batches.add(all.subList(i, Math.min(all.size(), i + BATCH)));
		}
		return batches;
	}
}
