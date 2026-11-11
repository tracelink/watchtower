package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository;

import java.util.Collection;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;

/**
 * Repository JPA for the pull request entities
 * 
 * @author csmith
 *
 */
@Repository(value = "prContainerRepository")
public interface PRContainerRepository
		extends IContainerRepository<PullRequestContainerEntity> {

	/**
	 * The newest row for a pull request. Older data holds duplicate rows for one pull request
	 * (V058 left the key non-unique for that reason), so a single-result lookup would throw.
	 */
	PullRequestContainerEntity findFirstByApiLabelAndRepoNameAndPrIdOrderByIdDesc(String apiLabel,
			String repoName, String prId);

	/** Every row for a pull request, duplicates included, so all of them can be resolved. */
	List<PullRequestContainerEntity> findByApiLabelAndRepoNameAndPrId(String apiLabel,
			String repoName, String prId);

	Page<PullRequestContainerEntity> findByResolvedFalse(Pageable pageable);

	Page<PullRequestContainerEntity> findByResolvedFalseAndLastReviewedDateBefore(
			long lastReviewedDateCutoffMillis, Pageable pageable);

	/** The sync cursor remains stable while earlier rows are marked resolved. */
	Slice<PullRequestContainerEntity> findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
			long lastReviewedDateCutoffMillis, long lastId, Pageable pageable);

	/** Unresolved pull requests reviewed since the cutoff: the results page's default window. */
	Page<PullRequestContainerEntity> findByResolvedFalseAndLastReviewedDateGreaterThanEqual(
			long lastReviewedDateCutoffMillis, Pageable pageable);

	/**
	 * One repository's pull requests, last reviewed first, without their scans (the entity loads
	 * every scan and finding eagerly).
	 *
	 * @param repoNames the names it has gone by: its slug, and the display name webhooks once
	 *                  stored
	 */
	@Query(value = "SELECT c.id AS id, c.prId AS prId, c.author AS author, "
			+ "c.sourceBranch AS sourceBranch, c.destinationBranch AS destinationBranch, "
			+ "c.resolved AS resolved, c.lastReviewedDate AS lastReviewedDate, "
			+ "c.closedState AS closedState "
			+ "FROM PullRequestContainerEntity c WHERE c.apiLabel = ?1 AND c.repoName IN ?2 "
			+ "ORDER BY c.lastReviewedDate DESC, c.id DESC",
			countQuery = "SELECT COUNT(c) FROM PullRequestContainerEntity c "
					+ "WHERE c.apiLabel = ?1 AND c.repoName IN ?2")
	Page<PullRequestSummary> findSummaries(String apiLabel, Collection<String> repoNames,
			Pageable pageable);

	/**
	 * Pull requests closed one way since a time, newest first, without their scans. Reads the
	 * (closed_state, closed_at) index.
	 *
	 * @param limit caps the rows read; the merge gate view says when it was reached
	 */
	@Query("SELECT c.id AS id, c.apiLabel AS apiLabel, c.repoName AS repoName, c.prId AS prId, "
			+ "c.closedAt AS closedAt, c.mergedCommit AS mergedCommit, "
			+ "c.scanPendingAtClose AS scanPendingAtClose FROM PullRequestContainerEntity c "
			+ "WHERE c.closedState = ?1 AND c.closedAt >= ?2 ORDER BY c.closedAt DESC, c.id DESC")
	List<ClosedPullRequest> findClosedSince(PullRequestState state, long since, Pageable limit);

	/**
	 * A closed pull request.
	 */
	interface ClosedPullRequest {
		long getId();

		String getApiLabel();

		String getRepoName();

		String getPrId();

		long getClosedAt();

		String getMergedCommit();

		Boolean getScanPendingAtClose();
	}

	/**
	 * A pull request's own fields.
	 */
	/**
	 * One repository's newest pull requests by number (open or closed), for "Last PR #58 · Open".
	 * Numbers are stored as text, so a longer number is newer before the text is compared.
	 *
	 * @param repoNames the names it has gone by: its slug, and the display name webhooks once
	 *                  stored
	 */
	@Query("SELECT c.id AS id, c.prId AS prId, c.author AS author, "
			+ "c.sourceBranch AS sourceBranch, c.destinationBranch AS destinationBranch, "
			+ "c.resolved AS resolved, c.lastReviewedDate AS lastReviewedDate, "
			+ "c.closedState AS closedState "
			+ "FROM PullRequestContainerEntity c WHERE c.apiLabel = ?1 AND c.repoName IN ?2 "
			+ "ORDER BY LENGTH(c.prId) DESC, c.prId DESC, c.id DESC")
	List<PullRequestSummary> findNewestSummaries(String apiLabel, Collection<String> repoNames,
			Pageable pageable);

	interface PullRequestSummary {
		long getId();

		String getPrId();

		String getAuthor();

		String getSourceBranch();

		String getDestinationBranch();

		boolean isResolved();

		long getLastReviewedDate();

		PullRequestState getClosedState();
	}
}
