package com.tracelink.appsec.watchtower.core.scan.scm.pr;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class PullRequestTest {
	public static final String label = "label";
	public static final String author = "author";
	public static final String sourceBranch = "source";
	public static final String destinationBranch = "dest";
	public static final String prId = "2";
	public static final String repoName = "foobar";
	public static final String prString = "foobar-2";
	public static final PullRequestState prState = PullRequestState.ACTIVE;
	public static final String commitHash = "123456789";
	public static final long updateTime = 1L;

	@Test
	public void PRDAOTest() {
		PullRequest pr = buildStandardPR();
		Assertions.assertEquals(label, pr.getApiLabel());
		Assertions.assertEquals(PullRequestState.ACTIVE, pr.getState());
		Assertions.assertEquals(author, pr.getAuthor());
		Assertions.assertEquals(sourceBranch, pr.getSourceBranch());
		Assertions.assertEquals(destinationBranch, pr.getDestinationBranch());
		Assertions.assertEquals(prId, pr.getPrId());
		Assertions.assertEquals(repoName, pr.getRepoName());
		Assertions.assertEquals(prString, pr.getPRString());
		Assertions.assertEquals(commitHash, pr.getCommitHash());
		Assertions.assertTrue(pr.hasAllData());
	}

	public static PullRequest buildStandardPR() {
		PullRequest pr = new PullRequest(label);
		pr.setAuthor(author);
		pr.setSourceBranch(sourceBranch);
		pr.setDestinationBranch(destinationBranch);
		pr.setPrId(prId);
		pr.setRepoName(repoName);
		pr.setState(prState);
		pr.setCommitHash(commitHash);
		pr.setUpdateTime(updateTime);
		return pr;
	}
}
