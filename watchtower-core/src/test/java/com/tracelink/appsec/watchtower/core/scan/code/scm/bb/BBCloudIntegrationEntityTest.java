package com.tracelink.appsec.watchtower.core.scan.code.scm.bb;

import java.util.HashMap;
import java.util.Map;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.RegisterState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudRejectOption;

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
		Assertions.assertEquals(ApiType.BITBUCKET_CLOUD, entity.getApiType());
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
		params.put("rejectOption", BBCloudRejectOption.DO_NOTHING.getName());

		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();
		entity.configureEntityFromParameters(params);
		Assertions.assertEquals(apiLabel, entity.getApiLabel());
		Assertions.assertEquals(ApiType.BITBUCKET_CLOUD, entity.getApiType());
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

	@Test
	public void testDefaultRegisterStateIsNotRegistered() {
		// IMPROVEMENT_PLAN.md item 8, point 6: Bitbucket supports self-registration, so a
		// fresh entity should offer the Register button rather than the base class's
		// NOT_SUPPORTED default.
		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();
		Assertions.assertEquals(RegisterState.NOT_REGISTERED, entity.getRegisterState());
	}

	@Test
	public void testWebhookUuidRoundTrip() {
		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();
		Assertions.assertNull(entity.getWebhookUuid());
		entity.setWebhookUuid("a-hook-uuid");
		Assertions.assertEquals("a-hook-uuid", entity.getWebhookUuid());
	}

	@Test
	public void testMakeWorkspaceHooksUrl() {
		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();
		entity.setWorkspace("myworkspace");
		Assertions.assertEquals("https://api.bitbucket.org/2.0/workspaces/myworkspace/hooks",
				entity.makeWorkspaceHooksUrl());
	}

	@Test
	public void testMakeFileLinkEncodesThePath() {
		BBCloudIntegrationEntity entity = new BBCloudIntegrationEntity();
		entity.setWorkspace("ws");
		Assertions.assertEquals("https://bitbucket.org/ws/repo/src/abc/src/My%20File.java#lines-7",
				entity.makeFileLink("repo", "abc", "src/My File.java", 7));
		// A path cannot add a query or replace the line fragment
		Assertions.assertEquals("https://bitbucket.org/ws/repo/src/abc/a%3Fx=1%23b",
				entity.makeFileLink("repo", "abc", "a?x=1#b", 0));
	}

}
