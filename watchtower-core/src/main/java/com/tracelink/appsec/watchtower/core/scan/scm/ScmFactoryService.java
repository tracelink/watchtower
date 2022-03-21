package com.tracelink.appsec.watchtower.core.scan.scm;

import java.util.Map;

import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.scm.api.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.api.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.scm.api.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.scm.api.bb.BBCloudApi;
import com.tracelink.appsec.watchtower.core.scan.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.api.bb.BBPullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequest;

/**
 * Handles logic around creating scanners, source clients, reporters, and pull requests for
 * scanning. This is used in conjunction with the {@linkplain APIIntegrationService} class.
 * <p>
 * Note to developers, when adding a new ApiType, add the corresponding logic here
 *
 * @author csmith, mcool
 */
@Service
public class ScmFactoryService {

	/**
	 * Given an ApiType and string representation of a pull request (usually from some automation),
	 * generate a pull request for the API type
	 *
	 * @param apiEntity   the Api entity descriptor for this PR
	 * @param pullRequest the string representation of a pull request used to generate the PR
	 * @return a PullRequest from the string data for this API
	 * @throws ApiIntegrationException if the api entity is null or the api type is unknown
	 */
	public PullRequest createPrFromAutomation(APIIntegrationEntity apiEntity, String pullRequest)
			throws ApiIntegrationException {
		if (apiEntity == null) {
			throw new ApiIntegrationException("Entity is null");
		}
		switch (apiEntity.getApiType()) {
			case BITBUCKET_CLOUD:
				BBPullRequest bbpr = new BBPullRequest(apiEntity.getApiLabel());
				bbpr.parseJsonFromWebhook(pullRequest);
				return bbpr;
			default:
				throw new ApiIntegrationException("No SCM API for this label.");
		}
	}

	/**
	 * Create and fill the correct entity for the given {@linkplain ScmApiType} and request parameters
	 * 
	 * @param type       the {@linkplain ScmApiType}
	 * @param parameters the request parameters
	 * @return an {@linkplain APIIntegrationEntity} filled with values from the request params
	 * @throws ApiIntegrationException if the api type is unknown, or the entity cannot be created
	 */
	public APIIntegrationEntity makeEntityForParams(ScmApiType type, Map<String, String> parameters)
			throws ApiIntegrationException {
		APIIntegrationEntity entity;
		switch (type) {
			case BITBUCKET_CLOUD:
				entity = new BBCloudIntegrationEntity();
				break;
			default:
				throw new ApiIntegrationException("No SCM API for this type.");
		}
		entity.configureEntityFromParameters(parameters);
		return entity;
	}

	/**
	 * Given an API entity, create the corresponding API client
	 * 
	 * @param apiEntity the API entity containing configuration information for an api
	 * @return an appropriate {@linkplain IScmApi} for this label
	 * @throws ApiIntegrationException if the api entity is null or the api type is unknown
	 */
	public IScmApi createApiForApiEntity(APIIntegrationEntity apiEntity)
			throws ApiIntegrationException {
		if (apiEntity == null) {
			throw new ApiIntegrationException("Entity is null");
		}
		switch (apiEntity.getApiType()) {
			case BITBUCKET_CLOUD:
				return new BBCloudApi((BBCloudIntegrationEntity) apiEntity);
			default:
				throw new ApiIntegrationException("No SCM API for this label.");
		}
	}

}
