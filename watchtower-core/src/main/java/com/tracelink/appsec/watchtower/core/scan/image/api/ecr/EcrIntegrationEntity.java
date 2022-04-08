package com.tracelink.appsec.watchtower.core.scan.image.api.ecr;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Table;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.encryption.converter.StringEncryptedAttributeConverter;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;

@Entity
@Table(name = "ecr_integration_entity")
public class EcrIntegrationEntity extends APIIntegrationEntity {

	@Column(name = "api_key")
	private String apiKey;

	@Column(name = "secret_key")
	@Convert(converter = StringEncryptedAttributeConverter.class)
	private String secretKey;

	public String getApiKey() {
		return apiKey;
	}

	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}

	@Override
	public ApiType getApiType() {
		return ApiType.ECR;
	}

	@Override
	public void configureEntityFromParameters(Map<String, String> parameters)
			throws ApiIntegrationException {
		List<String> neededParams =
				new ArrayList<>(Arrays.asList("apiLabel", "apiKey", "secretKey"));
		parameters.entrySet().removeIf(e -> StringUtils.isBlank(e.getValue()));
		neededParams.removeAll(parameters.keySet());

		if (!neededParams.isEmpty()) {
			throw new ApiIntegrationException("Missing value for "
					+ neededParams.stream().collect(Collectors.joining(", ")));
		}
		String apiLabel = parameters.get("apiLabel");
		setApiLabel(apiLabel);
		setApiKey(parameters.get("apiKey"));
		setSecretKey(parameters.get("secretKey"));
	}

	@Override
	public EcrApi createApi() throws ApiIntegrationException {
		return new EcrApi(this);
	}

}
