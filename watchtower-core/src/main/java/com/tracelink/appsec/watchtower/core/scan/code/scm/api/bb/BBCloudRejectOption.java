package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

public enum BBCloudRejectOption {
	DO_NOTHING("Do Nothing"),
	SEND_COMMENT("Send Comment"),
	BLOCK_PR("Send Comment and Block Pull Request"),
	;
	private String name;

	BBCloudRejectOption(String name) {
		this.name = name;
	}

	public String getName() {
		return this.name;
	}

	public static BBCloudRejectOption fromString(String string) {
		for (BBCloudRejectOption o : BBCloudRejectOption.values()) {
			if (o.getName().equals(string)) {
				return o;
			}
		}
		return BBCloudRejectOption.DO_NOTHING;
	}

	@Converter
	public static class BBCloudRejectOptionConverter
			implements AttributeConverter<BBCloudRejectOption, String> {

		@Override
		public String convertToDatabaseColumn(BBCloudRejectOption attribute) {
			return attribute.getName();
		}

		@Override
		public BBCloudRejectOption convertToEntityAttribute(String dbData) {
			return BBCloudRejectOption.fromString(dbData);
		}

	}
}
