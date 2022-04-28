package com.tracelink.appsec.watchtower.core.scan.image.api.ecr;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import kong.unirest.json.JSONObject;
import org.apache.commons.lang3.StringUtils;

/**
 * Populates information needed for an imagee scan request from AWS ECR.
 *
 * @author mcool
 */
public class EcrImageScan extends ImageScan {

	public EcrImageScan(String apiLabel) {
		super(apiLabel);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void populateFromRequest(String requestBody) throws ApiIntegrationException {
		JSONObject json = new JSONObject(requestBody);
		String registryId = json.getString("registryId");
		String repository = json.getString("repository");
		String tag = json.getJSONArray("tags").optString(0);
		if (StringUtils.isBlank(tag)) {
			throw new ApiIntegrationException("No image tag specified");
		}
		setRegistry(registryId);
		setRepository(repository);
		setTag(tag);
	}
}
