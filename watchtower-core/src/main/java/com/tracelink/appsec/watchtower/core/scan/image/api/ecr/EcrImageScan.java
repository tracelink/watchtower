package com.tracelink.appsec.watchtower.core.scan.image.api.ecr;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import kong.unirest.json.JSONArray;
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
		String registryId = json.optString("registryId");
		String repository = json.optString("repository");
		JSONArray tags = json.optJSONArray("tags");
		if (StringUtils.isBlank(registryId) || StringUtils.isBlank(repository) || tags == null
				|| tags.isEmpty() || tags.isNull(0)) {
			throw new ApiIntegrationException(
					"Required params are 'registryId', 'repository', and a nonempty 'tags' array");
		}

		setRegistry(registryId);
		setRepository(repository);
		setTag(tags.getString(0));
	}
}
