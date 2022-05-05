package com.tracelink.appsec.watchtower.core.scan.apiintegration;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrIntegrationEntity;

/**
 * Enumeration of all API types configured and understood in watchtower.
 *
 * @author csmith
 */
public enum ApiType {
	/**
	 * The Bitbucket API
	 */
	BITBUCKET_CLOUD("Bitbucket Cloud", "configuration/bbcloudconfigure") {
		@Override
		public ApiIntegrationEntity createApiIntegrationEntity() {
			return new BBCloudIntegrationEntity();
		}
	},
	ECR("Amazon ECR", "configuration/ecrconfigure") {
		@Override
		public ApiIntegrationEntity createApiIntegrationEntity() {
			return new EcrIntegrationEntity();
		}
	};

	private final String typeName;
	private final String template;


	ApiType(String typeName, String template) {
		this.typeName = typeName;
		this.template = template;
	}

	public String getTypeName() {
		return typeName;
	}

	/**
	 * Get the Template used to show a UI to create OR update this object's api entity. It is
	 * expected that the template should at least contain the entity's Label and ID as the
	 * parameters "apiLabel" and "apiId" respectively.
	 *
	 * @return the template name used for creating and updating an api entity for this type
	 */
	public String getTemplate() {
		return template;
	}

	/**
	 * Create API integration entity for this {@linkplain ApiType} from the given request parameters
	 *
	 * @return an {@linkplain ApiIntegrationEntity} filled with values from the request params
	 */
	public abstract ApiIntegrationEntity createApiIntegrationEntity();

	/**
	 * Given a string name of the API type, match to an ApiType object, or null if no match was made
	 *
	 * @param name the string representation of the ApiType
	 * @return an ApiType for this name, or null
	 */
	public static ApiType typeForName(String name) {
		for (ApiType t : ApiType.values()) {
			if (t.getTypeName().equalsIgnoreCase(name)) {
				return t;
			}
		}
		return null;
	}
}
