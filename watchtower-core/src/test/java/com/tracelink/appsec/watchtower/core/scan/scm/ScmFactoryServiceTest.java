package com.tracelink.appsec.watchtower.core.scan.scm;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.scan.scm.apiintegration.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.scm.bb.BBCloudApi;
import com.tracelink.appsec.watchtower.core.scan.scm.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.bb.BBPullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.bb.BBPullRequestTest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequestState;

@ExtendWith(SpringExtension.class)
public class ScmFactoryServiceTest {



	@Mock
	private PullRequest mockPR;

	private ScmFactoryService scannerFactory = new ScmFactoryService();


	@Test
	public void testCreatePrFromAutomation() throws Exception {
		APIIntegrationEntity entity = new BBCloudIntegrationEntity();
		PullRequest pr = scannerFactory.createPrFromAutomation(entity,
				BBPullRequestTest.buildStandardJSONString());
		Assertions.assertTrue(pr instanceof BBPullRequest);
		BBPullRequest bbpr = (BBPullRequest) pr;
		Assertions.assertEquals(BBPullRequestTest.author, bbpr.getAuthor());
		Assertions.assertEquals(BBPullRequestTest.sourceBranch, bbpr.getSourceBranch());
		Assertions.assertEquals(BBPullRequestTest.destinationBranch, bbpr.getDestinationBranch());
		Assertions.assertEquals(BBPullRequestTest.repo, bbpr.getRepoName());
		Assertions.assertEquals(BBPullRequestTest.prId, Integer.parseInt(bbpr.getPrId()));
		Assertions.assertEquals(PullRequestState.ACTIVE, bbpr.getState());
	}

	@Test
	public void testMakeEntityFromParams() throws ApiIntegrationException {
		String apiLabel = "A Label";
		String user = "user";
		String auth = "auth";
		String workspace = "work";
		Map<String, String> params = new HashMap<>();
		params.put("apiLabel", apiLabel);
		params.put("user", user);
		params.put("auth", auth);
		params.put("workspace", workspace);

		BBCloudIntegrationEntity entity =
				(BBCloudIntegrationEntity) scannerFactory
						.makeEntityForParams(ApiType.BITBUCKET_CLOUD, params);
		Assertions.assertEquals(apiLabel, entity.getApiLabel());
		Assertions.assertEquals(ApiType.BITBUCKET_CLOUD, entity.getApiType());
		Assertions.assertEquals(user, entity.getUser());
		Assertions.assertEquals(auth, entity.getAuth());
		Assertions.assertEquals(workspace, entity.getWorkspace());
	}

	@Test
	public void testCreateApiForApiEntity() throws ApiIntegrationException {
		IScmApi api = scannerFactory.createApiForApiEntity(new BBCloudIntegrationEntity());
		Assertions.assertTrue(api instanceof BBCloudApi);
	}

	@Test
	public void testCreateApiForApiLabelNull() throws ApiIntegrationException {
		Assertions.assertThrows(ApiIntegrationException.class,
				() -> {
					scannerFactory.createApiForApiEntity(null);
				});
	}

}
