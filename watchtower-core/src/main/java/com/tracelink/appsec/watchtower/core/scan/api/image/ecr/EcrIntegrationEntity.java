package com.tracelink.appsec.watchtower.core.scan.api.image.ecr;

import java.util.Map;

import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.api.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.api.ApiType;

public class EcrIntegrationEntity extends APIIntegrationEntity {

	@Override
	public ApiType getApiType() {
		return ApiType.ECR;
	}

	@Override
	public void configureEntityFromParameters(Map<String, String> parameters)
			throws ApiIntegrationException {
		// TODO Auto-generated method stub

	}

	@Override
	public String makePRLink(String repository, String pullRequestId) {
		// TODO Auto-generated method stub
		return null;
	}

}
