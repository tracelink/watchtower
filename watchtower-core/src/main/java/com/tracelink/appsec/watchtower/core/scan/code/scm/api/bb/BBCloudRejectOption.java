package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

public enum BBCloudRejectOption {
	DO_NOTHING("Do Nothing"),
	SEND_COMMENT("Send Comment"),
	BLOCK_PR("Send Comment and Block Pull Request"),
	/**
	 * Send the comment, then approve the PR when there are no new blocking violations or request
	 * changes when there are. Intended for a Watchtower service account configured as a default
	 * reviewer, with a Bitbucket merge check requiring its approval.
	 */
	APPROVE_OR_REQUEST_CHANGES("Send Comment and Approve or Request Changes"),
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
