package com.tracelink.appsec.watchtower.core.scan.code;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryPullRequestService;

/** Individual PR and full-repository scans in one chronologically paged desktop results list. */
@Service
public class CodeScanResultsService {
	public static final int PAGE_SIZE = 20;

	public enum Kind {
		ALL("all", "All"), PR("pr", "Pull requests"), REPOSITORY("repository", "Full repository");
		private final String key;
		private final String label;
		Kind(String key, String label) { this.key = key; this.label = label; }
		public String getKey() { return key; }
		public String getLabel() { return label; }
		public static Kind of(String key) {
			for (Kind kind : values()) if (kind.key.equals(key)) return kind;
			return ALL;
		}
	}

	private final PRScanRepository prs;
	private final PRViolationRepository violations;
	private final RepoScanRepository repositories;
	private final RepositoryPullRequestService repositoryPullRequests;

	public CodeScanResultsService(PRScanRepository prs, PRViolationRepository violations,
			RepoScanRepository repositories, RepositoryPullRequestService repositoryPullRequests) {
		this.prs = prs;
		this.violations = violations;
		this.repositories = repositories;
		this.repositoryPullRequests = repositoryPullRequests;
	}

	/** How many results each tab holds, for the tab counts (Fixes board 2026-10-22). */
	public record Counts(long pullRequests, long repository) {
		public long all() {
			return pullRequests + repository;
		}

		public long of(Kind kind) {
			return switch (kind) {
				case ALL -> all();
				case PR -> pullRequests;
				case REPOSITORY -> repository;
			};
		}
	}

	/**
	 * Tab counts for every result, or for one repository's results.
	 *
	 * @param repo the repository, or null for every repository
	 * @return pull request and full-repository scan counts
	 */
	@Transactional(readOnly = true)
	public Counts counts(RepositoryEntity repo) {
		if (repo == null) {
			return new Counts(prs.count(), repositories.count());
		}
		var repoNames = repositoryPullRequests.namesOf(repo.getApiLabel(), repo.getRepoName());
		return new Counts(prs.countResultRowsForRepository(repo.getApiLabel(), repoNames),
				repositories.countByRepositoryId(repo.getId()));
	}

	@Transactional(readOnly = true)
	public PagedResult<HomeActivityItem> page(Kind kind, int requestedPage, RepositoryEntity repo) {
		int page = Math.max(0, requestedPage);
		var repoNames = repo == null || kind == Kind.REPOSITORY ? java.util.Set.<String>of()
				: repositoryPullRequests.namesOf(repo.getApiLabel(), repo.getRepoName());
		long prTotal = kind == Kind.REPOSITORY ? 0 : repo == null ? prs.count()
				: prs.countResultRowsForRepository(repo.getApiLabel(), repoNames);
		long repoTotal = kind == Kind.PR ? 0 : repo == null ? repositories.count()
				: repositories.countByRepositoryId(repo.getId());
		long total = prTotal + repoTotal;
		int totalPages = (int) Math.min(Integer.MAX_VALUE,
				(total + PAGE_SIZE - 1) / PAGE_SIZE);
		if (totalPages == 0) page = 0;
		else if (page >= totalPages) page = totalPages - 1;
		int offset = Math.multiplyExact(page, PAGE_SIZE);
		int fetch = kind == Kind.ALL ? Math.addExact(offset, PAGE_SIZE) : PAGE_SIZE;
		PageRequest first = PageRequest.of(0, fetch);
		PageRequest direct = PageRequest.of(page, PAGE_SIZE);
		List<Entry> rows = new ArrayList<>();
		if (kind == Kind.ALL) {
			var prKeys = repo == null ? prs.findResultKeys(first)
					: prs.findResultKeysForRepository(repo.getApiLabel(), repoNames, first);
			var repoKeys = repo == null ? repositories.findResultKeys(first)
					: repositories.findResultKeysForRepository(repo.getId(), first);
			for (var key : prKeys) rows.add(new Entry(key.getEndDate(), key.getId(), true, null, null));
			for (var key : repoKeys) rows.add(new Entry(key.getEndDate(), key.getId(), false, null, null));
			rows.sort(Comparator.comparingLong(Entry::ended).reversed()
					.thenComparing(Comparator.comparingLong(Entry::id).reversed()));
			rows = rows.subList(Math.min(offset, rows.size()),
					Math.min(fetch, rows.size()));
			List<Long> selectedPrIds = rows.stream().filter(Entry::pullRequest).map(Entry::id).toList();
			List<Long> selectedRepoIds = rows.stream().filter(e -> !e.pullRequest()).map(Entry::id).toList();
			Map<Long, PRScanRepository.ResultRow> prDetails = new HashMap<>();
			Map<Long, RepoScanEntity> repoDetails = new HashMap<>();
			if (!selectedPrIds.isEmpty()) {
				prs.findResultRowsByIds(selectedPrIds).forEach(detail ->
						prDetails.put(detail.getId(), detail));
			}
			if (!selectedRepoIds.isEmpty()) {
				repositories.findResultRowsByIds(selectedRepoIds).forEach(detail ->
						repoDetails.put(detail.getId(), detail));
			}
			List<Entry> selected = new ArrayList<>(rows.size());
			for (Entry row : rows) {
				selected.add(new Entry(row.ended(), row.id(), row.pullRequest(),
						prDetails.get(row.id()), repoDetails.get(row.id())));
			}
			selected.removeIf(row -> row.pr() == null && row.repo() == null);
			rows = selected;
		} else if (kind == Kind.PR) {
			var prRows = repo == null ? prs.findResultRows(direct)
					: prs.findResultRowsForRepository(repo.getApiLabel(), repoNames, direct);
			for (var pr : prRows) rows.add(new Entry(pr.getEndDate(), pr.getId(), true, pr, null));
		} else {
			var repoRows = repo == null ? repositories.findResultRows(direct)
					: repositories.findResultRowsForRepository(repo.getId(), direct);
			for (var scan : repoRows) rows.add(new Entry(scan.getEndDate(), scan.getId(), false, null, scan));
		}
		Map<Long, Map<RulePriority, Long>> counts = new HashMap<>();
		Map<Long, Long> mcr = new HashMap<>();
		List<Long> prIds = rows.stream().filter(e -> e.pr() != null).map(e -> e.pr().getId()).toList();
		if (!prIds.isEmpty()) {
			for (Object[] result : violations.countSeveritiesByScanId(prIds)) {
				counts.computeIfAbsent(((Number) result[0]).longValue(), ignored ->
						new EnumMap<>(RulePriority.class))
						.merge(result[1] == null ? RulePriority.INFORMATIONAL
								: (RulePriority) result[1], ((Number) result[2]).longValue(), Long::sum);
			}
			for (Object[] result : violations.countMcrByScanId(prIds)) {
				mcr.put(((Number) result[0]).longValue(), ((Number) result[1]).longValue());
			}
		}
		List<HomeActivityItem> items = rows.stream().map(row -> row.pr() == null
				? HomeActivityItem.fromRepo(row.repo())
				: HomeActivityItem.fromPullRequestRow(row.pr(),
						counts.getOrDefault(row.pr().getId(), Map.of()),
						mcr.getOrDefault(row.pr().getId(), 0L))).toList();
		return new PagedResult<>(items, page, PAGE_SIZE, total, totalPages);
	}

	private record Entry(long ended, long id, boolean pullRequest,
			PRScanRepository.ResultRow pr, RepoScanEntity repo) { }
}
