package com.tracelink.appsec.watchtower.core.scan.api;

import java.util.Map;

import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.api.image.ecr.EcrApi;
import com.tracelink.appsec.watchtower.core.scan.api.image.ecr.EcrIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.api.scm.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.api.scm.bb.BBCloudApi;
import com.tracelink.appsec.watchtower.core.scan.api.scm.bb.BBCloudIntegrationEntity;

/**
 * Handles logic around creating scanners, source clients, reporters, and pull requests for
 * scanning. This is used in conjunction with the {@linkplain APIIntegrationService} class.
 * <p>
 * Note to developers, when adding a new ApiType, add the corresponding logic here
 *
 * @author csmith, mcool
 */
@Service
public class ApiFactoryService {

	/**
	 * Create and fill the correct entity for the given {@linkplain ApiType} and request parameters
	 * 
	 * @param type       the {@linkplain ApiType}
	 * @param parameters the request parameters
	 * @return an {@linkplain APIIntegrationEntity} filled with values from the request params
	 * @throws ApiIntegrationException if the api type is unknown, or the entity cannot be created
	 */
	public APIIntegrationEntity makeEntityForParams(ApiType type, Map<String, String> parameters)
			throws ApiIntegrationException {
		APIIntegrationEntity entity;
		switch (type) {
			case BITBUCKET_CLOUD:
				entity = new BBCloudIntegrationEntity();
				break;
			case ECR:
				entity = new EcrIntegrationEntity();
			default:
				throw new ApiIntegrationException("No API for this type.");
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
	public IWatchtowerApi createApiForApiEntity(APIIntegrationEntity apiEntity)
			throws ApiIntegrationException {
		if (apiEntity == null) {
			throw new ApiIntegrationException("Entity is null");
		}
		switch (apiEntity.getApiType()) {
			case BITBUCKET_CLOUD:
				return new BBCloudApi((BBCloudIntegrationEntity) apiEntity);
			case ECR:
				return new EcrApi();
			default:
				throw new ApiIntegrationException("No API for this label.");
		}
	}

}
