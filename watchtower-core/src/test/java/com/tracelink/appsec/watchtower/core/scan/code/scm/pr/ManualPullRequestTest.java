package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.ManualPullRequest;

public class ManualPullRequestTest {

	@Test
	public void testDAO() {
		String repoName = "repoName";
		String prid = "prid";
		String type = "bitbucket";

		ManualPullRequest pr = new ManualPullRequest();
		pr.setPrid(prid);
		pr.setRepo(repoName);
		pr.setApiLabel(type);

		Assertions.assertEquals(repoName, pr.getRepo());
		Assertions.assertEquals(prid, pr.getPrid());
		Assertions.assertEquals(type, pr.getApiLabel());
	}

}
