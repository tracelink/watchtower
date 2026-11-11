package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;

public class PullRequestEntityTest {

	@Test
	public void testDAO() {
		long lastReviewedDate = System.currentTimeMillis();
		boolean resolved = true;
		String apiLabel = "label";
		String author = "author";
		String sourceBranch = "srcBranch";
		String destinationBranch = "dstBranch";
		String prId = "prId";
		String repoName = "repo";

		PullRequestContainerEntity entity = new PullRequestContainerEntity();
		entity.setLastReviewedDate(lastReviewedDate);
		entity.setResolved(resolved);
		entity.setApiLabel(apiLabel);
		entity.setAuthor(author);
		entity.setSourceBranch(sourceBranch);
		entity.setDestinationBranch(destinationBranch);
		entity.setPrId(prId);
		entity.setRepoName(repoName);

		Assertions.assertEquals(lastReviewedDate, entity.getLastReviewedDate());
		Assertions.assertEquals(resolved, entity.isResolved());
		Assertions.assertEquals(apiLabel, entity.getApiLabel());
		Assertions.assertEquals(author, entity.getAuthor());
		Assertions.assertEquals(sourceBranch, entity.getSourceBranch());
		Assertions.assertEquals(destinationBranch, entity.getDestinationBranch());
		Assertions.assertEquals(prId, entity.getPrId());
		Assertions.assertEquals(repoName, entity.getRepoName());

	}

	@Test
	public void testConvert() {
		String apiLabel = "label";
		String author = "author";
		String sourceBranch = "srcBranch";
		String destinationBranch = "dstBranch";
		String prId = "prId";
		String repoName = "repo";

		PullRequest pr = new PullRequest(apiLabel);
		pr.setAuthor(author);
		pr.setSourceBranch(sourceBranch);
		pr.setDestinationBranch(destinationBranch);
		pr.setRepoName(repoName);
		pr.setPrId(prId);

		PullRequestContainerEntity newEntity = new PullRequestContainerEntity(pr);

		Assertions.assertEquals(apiLabel, newEntity.getApiLabel());
		Assertions.assertEquals(author, newEntity.getAuthor());
		Assertions.assertEquals(sourceBranch, newEntity.getSourceBranch());
		Assertions.assertEquals(destinationBranch, newEntity.getDestinationBranch());
		Assertions.assertEquals(prId, newEntity.getPrId());
		Assertions.assertEquals(repoName, newEntity.getRepoName());

		PullRequest round = newEntity.toPullRequest();

		Assertions.assertEquals(apiLabel, round.getApiLabel());
		Assertions.assertEquals(author, round.getAuthor());
		Assertions.assertEquals(sourceBranch, round.getSourceBranch());
		Assertions.assertEquals(destinationBranch, round.getDestinationBranch());
		Assertions.assertEquals(prId, round.getPrId());
		Assertions.assertEquals(repoName, round.getRepoName());
	}


	@Test
	public void aReopenSeenAfterTheCloseForgetsItButAScanThatRacedTheMergeDoesNot() {
		PullRequestContainerEntity entity = new PullRequestContainerEntity();
		entity.recordClosed(PullRequestState.DECLINED, 1_000L, null, false);

		// A scan whose state was fetched before the decline also says ACTIVE
		entity.recordOpen(PullRequestState.ACTIVE, 900L);
		Assertions.assertEquals(PullRequestState.DECLINED, entity.getClosedState());

		// Reopened after the decline
		entity.recordOpen(PullRequestState.ACTIVE, 2_000L);
		Assertions.assertNull(entity.getClosedState());
		Assertions.assertNull(entity.getClosedAt());
	}

	@Test
	public void aMergeReplacesADeclineButNotAnEarlierMerge() {
		PullRequestContainerEntity entity = new PullRequestContainerEntity();
		entity.recordClosed(PullRequestState.DECLINED, 1_000L, null, true);
		entity.recordClosed(PullRequestState.MERGED, 3_000L, "abc", false);

		Assertions.assertEquals(PullRequestState.MERGED, entity.getClosedState());
		Assertions.assertEquals(3_000L, entity.getClosedAt());
		Assertions.assertEquals("abc", entity.getMergedCommit());
		Assertions.assertFalse(entity.isScanPendingAtClose(), "pending belonged to the decline");

		entity.recordClosed(PullRequestState.MERGED, 9_000L, "def", false);
		Assertions.assertEquals(3_000L, entity.getClosedAt());
		Assertions.assertEquals("abc", entity.getMergedCommit());
	}
}
