package com.tracelink.appsec.module.advisory.model;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

public enum AdvisoryType {
	CVE("CVE"),
	RHSA("RHSA");

	private final String typeName;

	private AdvisoryType(String typeName) {
		this.typeName = typeName;
	}

	public String getTypeName() {
		return this.typeName;
	}

	public static AdvisoryType typeForName(String name) {
		for (AdvisoryType type : AdvisoryType.values()) {
			if (type.getTypeName().equals(name)) {
				return type;
			}
		}
		return null;
	}

	/**
	 * Converts the {@linkplain AdvisoryType} into a String for storage in the DB
	 *
	 * @author csmith
	 */
	@Converter
	public static class AdvisoryTypeConverter implements AttributeConverter<AdvisoryType, String> {

		@Override
		public String convertToDatabaseColumn(AdvisoryType attribute) {
			return attribute.getTypeName();
		}

		@Override
		public AdvisoryType convertToEntityAttribute(String dbData) {
			return AdvisoryType.typeForName(dbData);
		}

	}
}
