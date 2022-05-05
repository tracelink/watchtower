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
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.RegisterState;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrRejectOption.EcrRejectOptionConverter;

/**
 * Entity for the ECR Integration API
 *
 * @author csmith
 */
@Entity
@Table(name = "ecr_integration_entity")
public class EcrIntegrationEntity extends ApiIntegrationEntity {

	@Column(name = "region")
	private String region;

	@Column(name = "registryId")
	private String registryId;

	@Column(name = "aws_access_key")
	private String awsAccessKey;

	@Column(name = "aws_secret_key")
	@Convert(converter = StringEncryptedAttributeConverter.class)
	private String awsSecretKey;

	@Column(name = "reject_option")
	@Convert(converter = EcrRejectOptionConverter.class)
	private EcrRejectOption rejectOption;

	public EcrIntegrationEntity() {
		setRegisterState(RegisterState.NOT_REGISTERED);
	}

	public String getRegion() {
		return region;
	}

	public void setRegion(String region) {
		this.region = region;
	}

	public String getRegistryId() {
		return registryId;
	}

	public void setRegistryId(String registryId) {
		this.registryId = registryId;
	}

	public String getAwsAccessKey() {
		return awsAccessKey;
	}

	public void setAwsAccessKey(String awsAccessKey) {
		this.awsAccessKey = awsAccessKey;
	}

	public String getAwsSecretKey() {
		return awsSecretKey;
	}

	public void setAwsSecretKey(String awsSecretKey) {
		this.awsSecretKey = awsSecretKey;
	}

	public EcrRejectOption getRejectOption() {
		return rejectOption;
	}

	public void setRejectOption(EcrRejectOption rejectOption) {
		this.rejectOption = rejectOption;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ApiType getApiType() {
		return ApiType.ECR;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ScanType getScanType() {
		return ImageScanType.CONTAINER;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void configureEntityFromParameters(Map<String, String> parameters)
			throws ApiIntegrationException {
		List<String> neededParams =
				new ArrayList<>(
						Arrays.asList("apiLabel", "region", "registryId", "awsAccessKey",
								"awsSecretKey", "rejectOption"));
		parameters.entrySet().removeIf(e -> StringUtils.isBlank(e.getValue()));
		neededParams.removeAll(parameters.keySet());

		if (!neededParams.isEmpty()) {
			throw new ApiIntegrationException("Missing value for "
					+ neededParams.stream().collect(Collectors.joining(", ")));
		}
		setApiLabel(parameters.get("apiLabel"));
		setRegion(parameters.get("region"));
		setRegistryId(parameters.get("registryId"));
		setAwsAccessKey(parameters.get("awsAccessKey"));
		setAwsSecretKey(parameters.get("awsSecretKey"));
		setRejectOption(EcrRejectOption.fromString(parameters.get("rejectOption")));
		setRegisterState(RegisterState.NOT_REGISTERED);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public EcrApi createApi() {
		return new EcrApi(this);
	}

	public String getEndpointLink() {
		return "/rest/imagescan/" + getApiLabel();
	}
}
