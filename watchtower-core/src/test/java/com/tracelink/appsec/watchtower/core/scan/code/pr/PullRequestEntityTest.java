package com.tracelink.appsec.watchtower.core.scan.code.pr;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.pr.entity.PullRequestContainerEntity;

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

}
