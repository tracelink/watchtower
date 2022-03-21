package com.tracelink.appsec.watchtower.core.scan.scm.bb;

import java.util.HashMap;
import java.util.Map;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.scm.ScmApiType;
import com.tracelink.appsec.watchtower.core.scan.scm.api.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.scm.api.bb.BBCloudIntegrationEntity;

public class BBCloudIntegrationEntityTest {

	@Test
	public void testDAO() {
		String apiLabel = "A Label";
		String user = "user";
		String auth = "auth";
		String workspace = "work";
		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();
		entity.setApiLabel(apiLabel);
		entity.setWorkspace(workspace);
		entity.setUser(user);
		entity.setAuth(auth);
		Assertions.assertEquals(apiLabel, entity.getApiLabel());
		Assertions.assertEquals(ScmApiType.BITBUCKET_CLOUD, entity.getApiType());
		Assertions.assertEquals(user, entity.getUser());
		Assertions.assertEquals(auth, entity.getAuth());
		Assertions.assertEquals(workspace, entity.getWorkspace());
		String apiBase = "https://api.bitbucket.org/2.0";
		Assertions.assertEquals(apiBase, entity.getApiBase());
		MatcherAssert.assertThat(entity.makeApiWorkspaceUrl(), Matchers
				.allOf(Matchers.containsString(apiBase), Matchers.containsString(workspace)));
		String repoName = "repo";
		MatcherAssert.assertThat(entity.makeApiRepoUrl(repoName), Matchers
				.allOf(Matchers.containsString(apiBase), Matchers.containsString(workspace),
						Matchers.containsString(repoName)));
		String prid = "123";
		MatcherAssert.assertThat(entity.makeApiPRUrl(repoName, prid), Matchers
				.allOf(Matchers.containsString(apiBase), Matchers.containsString(workspace),
						Matchers.containsString(repoName), Matchers.containsString(prid)));

		MatcherAssert.assertThat(entity.makePRLink(repoName, prid), Matchers
				.allOf(Matchers.not(Matchers.containsString(apiBase)),
						Matchers.containsString(workspace),
						Matchers.containsString(repoName), Matchers.containsString(prid)));
	}

	@Test
	public void testEntityFromParams() throws ApiIntegrationException {
		String apiLabel = "A Label";
		String user = "user";
		String auth = "auth";
		String workspace = "work";
		Map<String, String> params = new HashMap<>();
		params.put("apiLabel", apiLabel);
		params.put("user", user);
		params.put("auth", auth);
		params.put("workspace", workspace);

		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();
		entity.configureEntityFromParameters(params);
		Assertions.assertEquals(apiLabel, entity.getApiLabel());
		Assertions.assertEquals(ScmApiType.BITBUCKET_CLOUD, entity.getApiType());
		Assertions.assertEquals(user, entity.getUser());
		Assertions.assertEquals(auth, entity.getAuth());
		Assertions.assertEquals(workspace, entity.getWorkspace());
	}

	@Test
	public void testEntityFromParamsMissing() {
		String apiLabel = "A Label";
		String user = "user";
		String auth = "auth";
		Map<String, String> params = new HashMap<>();
		params.put("apiLabel", apiLabel);
		params.put("user", user);
		params.put("auth", auth);

		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();

		try {
			entity.configureEntityFromParameters(params);
			Assertions.fail("Should throw exception");
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("workspace"));
		}
	}

}
