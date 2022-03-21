package com.tracelink.appsec.watchtower.core.scan.scm;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

/**
 * Enumeration of all API types configured and understood in watchtower.
 * <p>
 * Note to developers, to add a new api type, put a label here, add logic to
 * {@linkplain ScmFactoryService}, and implement anything needed from those methods (Pull Request,
 * API, etc)
 *
 * @author csmith
 */
public enum ScmApiType {
	/**
	 * The Bitbucket API
	 */
	BITBUCKET_CLOUD("Bitbucket Cloud", "configuration/bbcloudconfigure"),
	// CODECOMMIT("CodeCommit")
	;

	private final String typeName;
	private final String template;


	ScmApiType(String typeName, String template) {
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
	 * Given a string name of the API type, match to an ApiType object, or null if no match was made
	 *
	 * @param name the string representation of the ApiType
	 * @return an ApiType for this name, or null
	 */
	public static ScmApiType typeForName(String name) {
		for (ScmApiType t : ScmApiType.values()) {
			if (t.getTypeName().equalsIgnoreCase(name)) {
				return t;
			}
		}
		return null;
	}

	/**
	 * Converts the {@linkplain ScmApiType} into a String for storage in the DB
	 *
	 * @author csmith
	 */
	@Converter
	public static class ApiTypeConverter implements AttributeConverter<ScmApiType, String> {

		@Override
		public String convertToDatabaseColumn(ScmApiType attribute) {
			return attribute.getTypeName();
		}

		@Override
		public ScmApiType convertToEntityAttribute(String dbData) {
			return ScmApiType.typeForName(dbData);
		}

	}
}
