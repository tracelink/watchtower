package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.BinaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.AbstractScmIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository.PullRequestSummary;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository.LatestScan;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao.Catalog;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.catalog.RepoCatalogDao.CatalogRow;

/**
 * A repository's pull requests and their newest scans, for the repository page. Pull requests
 * belong to a repository by integration and repository name, so a repository deleted and added
 * back keeps its history. One page costs two indexed reads, whatever the page holds.
 *
 * @author Watchtower
 */
@Service
public class RepositoryPullRequestService {

	static final int PAGE_SIZE = 20;

	private final PRContainerRepository pullRequests;

	private final PRScanRepository scans;

	private final ApiIntegrationService integrations;

	private final RepoCatalogDao catalog;

	public RepositoryPullRequestService(PRContainerRepository pullRequests,
			PRScanRepository scans, ApiIntegrationService integrations, RepoCatalogDao catalog) {
		this.pullRequests = pullRequests;
		this.scans = scans;
		this.integrations = integrations;
		this.catalog = catalog;
	}

	/**
	 * @return one page of the repository's pull requests, last reviewed first: those stored
	 *         under its name and under any other name with the same slug (webhooks stored the
	 *         display name, "Payments API", before they stored the slug)
	 */
	public Page<PullRequestRow> page(String apiLabel, String repoName, int page) {
		Page<PullRequestSummary> summaries = pullRequests.findSummaries(apiLabel,
				namesOf(apiLabel, repoName), PageRequest.of(Math.max(0, page), PAGE_SIZE));
		if (summaries.isEmpty()) {
			return summaries.map(s -> toRow(s, null, null));
		}
		Map<Long, LatestScan> latest = scans.findLatestByContainerIds(
				summaries.map(PullRequestSummary::getId).getContent()).stream()
				.collect(Collectors.toMap(LatestScan::getContainerId, s -> s, newerScan()));
		AbstractScmIntegrationEntity scm =
				integrations.findByLabel(apiLabel) instanceof AbstractScmIntegrationEntity e
						? e : null;
		return summaries.map(s -> toRow(s, latest.get(s.getId()),
				scm == null ? null : scm.makePRLink(repoName, s.getPrId())));
	}

	/**
	 * @return the repository's newest pull request by number, open or closed, from the pull
	 *         requests themselves, so it is right even when the repository row was re-created by
	 *         a sync after its pull requests were scanned. Not the most recently reviewed one: an
	 *         older pull request re-reviewed later must not hide a newer open one (#57 vs #58).
	 */
	public java.util.Optional<PullRequestSummary> latest(String apiLabel, String repoName) {
		return pullRequests.findNewestSummaries(apiLabel, namesOf(apiLabel, repoName),
				PageRequest.of(0, 1)).stream().findFirst();
	}

	public Set<String> namesOf(String apiLabel, String repoName) {
		String key = RepoCatalogDao.nameKey(repoName);
		Catalog rows = catalog.rows(apiLabel);
		Set<String> names = new HashSet<>();
		names.add(repoName);
		Stream.concat(Stream.ofNullable(rows.byKey().get(key)), rows.shadowed().stream())
				.map(CatalogRow::name).filter(name -> RepoCatalogDao.nameKey(name).equals(key))
				.forEach(names::add);
		return names;
	}

	/** Two scans submitted in the same millisecond: the later one has the higher id. */
	private static BinaryOperator<LatestScan> newerScan() {
		return (a, b) -> a.getScanId() >= b.getScanId() ? a : b;
	}

	private static PullRequestRow toRow(PullRequestSummary pr, LatestScan scan, String link) {
		return new PullRequestRow(pr.getPrId(), pr.getAuthor(), pr.getSourceBranch(),
				pr.getDestinationBranch(), pr.isResolved(), pr.getClosedState(),
				pr.getLastReviewedDate(),
				scan == null ? null : scan.getScanId(), scan == null ? null : scan.getStatus(),
				scan != null && scan.isBlocked(), scan == null ? 0 : scan.getFindings(), link);
	}

	/**
	 * One pull request on the repository page.
	 *
	 * @param closedState MERGED or DECLINED once the SCM said so; null while open, and for pull
	 *                    requests closed before that was recorded
	 * @param scanId   its newest scan, or null if it was never scanned
	 * @param status   that scan's status, or null
	 * @param findings that scan's findings, as its report counts them
	 * @param link     the pull request in the SCM, or null if its integration is gone
	 */
	public record PullRequestRow(String prId, String author, String sourceBranch,
			String destinationBranch, boolean resolved, PullRequestState closedState,
			long lastReviewedDate, Long scanId,
			ScanStatus status, boolean blocked, long findings, String link) {
	}
}
