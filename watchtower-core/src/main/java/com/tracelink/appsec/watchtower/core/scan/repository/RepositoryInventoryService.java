package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.IntegrationHealthService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/**
 * Gathers what the repository inventory shows, in a few indexed reads on {@code repositories}
 * (counts, label menu, last sync) plus one read of the listed repositories' latest scans.
 *
 * @author Watchtower
 */
@Service
public class RepositoryInventoryService {

	static final int SCANS_PAGE = 20;

	private final RepositoryService repositories;

	private final RepositoryRepository repoRepo;

	private final RepositoryStatusService statuses;

	private final ApiIntegrationService integrations;

	private final RepoScanRepository scans;

	private final IntegrationHealthService health;

	public RepositoryInventoryService(RepositoryService repositories,
			RepositoryRepository repoRepo, RepositoryStatusService statuses,
			ApiIntegrationService integrations, RepoScanRepository scans,
			IntegrationHealthService health) {
		this.repositories = repositories;
		this.repoRepo = repoRepo;
		this.statuses = statuses;
		this.integrations = integrations;
		this.scans = scans;
		this.health = health;
	}

	/**
	 * @return one tab per integration of this type, plus one per deleted integration that still
	 *         has repositories (so they can be cleaned up), sorted
	 */
	public List<Tab> tabs(ScanType type) {
		TreeSet<String> labels = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
		Set<String> failing = new HashSet<>();
		for (ApiIntegrationEntity integration : integrations.getAllSettings()) {
			if (type.equals(integration.getScanType()) && integration.getApiLabel() != null) {
				labels.add(integration.getApiLabel());
				if (health.isFailing(integration)) {
					failing.add(integration.getApiLabel());
				}
			}
		}
		labels.addAll(repositories.getApiLabels(type));
		return labels.stream().map(label -> new Tab(label, statuses.isOrphaned(label),
				failing.contains(label))).toList();
	}

	/**
	 * @return one page of the inventory, each repository with its status, reason, last commit
	 *         and latest repository scan
	 */
	public Page<Row> rows(ScanType type, String apiLabel, RepositoryFilter filter,
			Pageable pageable) {
		Page<RepositoryEntity> page = repositories.list(type, apiLabel, filter, pageable);
		Map<Long, RepoScanEntity> lastScans = scans.findAllById(page.getContent().stream()
				.map(RepositoryEntity::getLastRepoScanId).filter(Objects::nonNull).toList())
				.stream().collect(Collectors.toMap(RepoScanEntity::getId, Function.identity()));
		return page.map(repo -> row(repo, repo.getLastRepoScanId() == null ? null
				: lastScans.get(repo.getLastRepoScanId())));
	}

	/**
	 * @return one repository as an inventory row, for its own page
	 */
	public Optional<Row> row(long id) {
		return repoRepo.findById(id).map(repo -> row(repo, repo.getLastRepoScanId() == null ? null
				: scans.findById(repo.getLastRepoScanId()).orElse(null)));
	}

	/**
	 * Deletes every repository of an integration and their repository scans,
	 * {@value RepositoryService#MAX_BULK} at a time, each batch in its own transaction (through
	 * the repository service's proxy). Repositories being scanned are left, as one delete leaves
	 * them.
	 *
	 * @param apiLabel the integration, usually a deleted one
	 * @param user     who asked, for the log
	 * @return what was deleted, and how many were left because they are being scanned
	 */
	public RepositoryService.DeleteResult deleteAllOf(String apiLabel, String user) {
		List<Long> ids = repositories.idsOfIntegration(apiLabel);
		int deleted = 0;
		int busy = 0;
		for (int from = 0; from < ids.size(); from += RepositoryService.MAX_BULK) {
			RepositoryService.DeleteResult batch = repositories.delete(ids.subList(from,
					Math.min(ids.size(), from + RepositoryService.MAX_BULK)), user);
			deleted += batch.deleted();
			busy += batch.busy();
		}
		return new RepositoryService.DeleteResult(deleted, busy);
	}

	/**
	 * @return one page of a repository's scans, newest first
	 */
	public Page<RepoScanEntity> scans(long repositoryId, int page) {
		return scans.findByRepositoryIdOrderBySubmitDateDesc(repositoryId,
				PageRequest.of(Math.max(0, page), SCANS_PAGE));
	}

	/**
	 * @param anyOrphaned whether some tab is a deleted integration
	 * @return the tab's totals for the meta line; orphaned counts every deleted integration's
	 *         repositories of this type
	 */
	public Counts counts(ScanType type, String apiLabel, boolean anyOrphaned) {
		RepositoryFilter all = RepositoryFilter.NONE;
		return new Counts(repoRepo.count(statuses.matching(type, apiLabel, all)),
				repoRepo.count(statuses.matching(type, apiLabel,
						all.withStatus(RepoStatus.GONE))),
				repoRepo.count(statuses.matching(type, apiLabel,
						all.withStatus(RepoStatus.PAUSED))),
				// Not indexed by api_label alone, so only counted when a deleted integration has
				// repositories at all (a tab shows it)
				anyOrphaned ? repoRepo.count(statuses.matching(type, null,
						all.withStatus(RepoStatus.ORPHANED))) : 0,
				repoRepo.findLastSync(apiLabel));
	}

	/** @return the labels used in the integration, sorted, for the label menu */
	public List<String> labels(ScanType type, String apiLabel) {
		return repoRepo.findLabelSets(type, apiLabel).stream()
				.flatMap(stored -> RepoLabels.parse(stored).stream()).distinct().sorted()
				.toList();
	}

	/** @return how many repositories still in the SCM a repository scan covers */
	public Coverage coverage(ScanType type) {
		return new Coverage(repoRepo.count(statuses.inScm(type, null)),
				repoRepo.count(statuses.inScm(type, RepoCoverage.RECENT)),
				repoRepo.count(statuses.inScm(type, RepoCoverage.NEVER)));
	}

	private Row row(RepositoryEntity repo, RepoScanEntity lastScan) {
		long lastScanEnd = lastScan == null ? 0 : lastScan.getEndDate();
		return new Row(repo, statuses.statusOf(repo), statuses.reason(repo),
				repo.getLastCommitAt() > 0 ? statuses.ago(repo.getLastCommitAt()) + " ago" : "",
				lastScan, lastScanEnd > 0 ? statuses.ago(lastScanEnd) + " ago" : "");
	}

	/** @return how long ago, e.g. "2 h ago" */
	public String ago(Long epochMillis) {
		return epochMillis == null || epochMillis <= 0 ? "never"
				: statuses.ago(epochMillis) + " ago";
	}

	/**
	 * An integration tab.
	 *
	 * @param label    the integration's name
	 * @param orphaned true if the integration was deleted
	 * @param failing  true if its last connection check, within a day, failed
	 */
	public record Tab(String label, boolean orphaned, boolean failing) {

		public Tab(String label, boolean orphaned) {
			this(label, orphaned, false);
		}
	}

	/**
	 * A row of the inventory.
	 *
	 * @param repo       the repository
	 * @param status     its status chip
	 * @param reason     why it has the status, for the chip's popover
	 * @param lastCommit how long ago it last changed, empty if unknown
	 * @param lastScan   its latest finished repository scan, or null
	 */
	public record Row(RepositoryEntity repo, RepoStatus status, String reason,
			String lastCommit, RepoScanEntity lastScan, String lastScanAgo) {

		public Row(RepositoryEntity repo, RepoStatus status, String reason, String lastCommit,
				RepoScanEntity lastScan) {
			this(repo, status, reason, lastCommit, lastScan, "");
		}
	}

	/**
	 * The inventory's meta line.
	 *
	 * @param total    repositories in the tab
	 * @param gone     of them, gone from the SCM
	 * @param paused   of them, paused
	 * @param orphaned repositories of deleted integrations, any tab
	 * @param lastSync when a sync last listed the tab's repositories, null if never
	 */
	public record Counts(long total, long gone, long paused, long orphaned, Long lastSync) {
	}

	/**
	 * The dashboard's coverage line.
	 *
	 * @param total  repositories still in the SCM
	 * @param recent of them, scanned in the last 30 days
	 * @param never  of them, never scanned
	 */
	public record Coverage(long total, long recent, long never) {

		/** @return the share scanned in the last 30 days, 0 to 100 */
		public long percent() {
			return total == 0 ? 0 : Math.round(recent * 100.0 / total);
		}
	}
}
