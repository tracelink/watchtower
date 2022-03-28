package com.tracelink.appsec.watchtower.core.scan.api.image.ecr;

import java.util.Map;

import javax.persistence.Entity;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.api.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.api.ApiType;

@Entity
@Table(name = "ecr_integration_entity")
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

}
