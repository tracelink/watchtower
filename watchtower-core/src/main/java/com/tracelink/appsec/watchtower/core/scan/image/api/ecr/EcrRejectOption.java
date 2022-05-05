package com.tracelink.appsec.watchtower.core.scan.image.api.ecr;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

public enum EcrRejectOption {
	DO_NOTHING("Do Nothing"),
	DELETE_IMAGE("Delete Image"),
	;
	private String name;

	EcrRejectOption(String name) {
		this.name = name;
	}

	public String getName() {
		return this.name;
	}

	public static EcrRejectOption fromString(String string) {
		for (EcrRejectOption o : EcrRejectOption.values()) {
			if (o.getName().equals(string)) {
				return o;
			}
		}
		return EcrRejectOption.DO_NOTHING;
	}

	@Converter
	public static class EcrRejectOptionConverter
			implements AttributeConverter<EcrRejectOption, String> {

		@Override
		public String convertToDatabaseColumn(EcrRejectOption attribute) {
			return attribute.getName();
		}

		@Override
		public EcrRejectOption convertToEntityAttribute(String dbData) {
			return EcrRejectOption.fromString(dbData);
		}

	}
}
