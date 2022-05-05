package com.tracelink.appsec.watchtower.core.scan;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;

/**
 * Represents the type of a Watchtower scan and provides a method to get a display name for the UI.
 *
 * @author csmith
 */
public interface ScanType extends Serializable {

	String getTypeName();

	String getDisplayName();

	/**
	 * Attribute Converter to manage translating between database-stored values and Java Objects
	 * 
	 * @author csmith
	 *
	 */
	@Converter
	class ScanTypeConverter implements AttributeConverter<ScanType, String> {

		private static final List<ScanType> TYPES = new ArrayList<>();

		public ScanTypeConverter() {
			TYPES.addAll(Arrays.asList(CodeScanType.values()));
			TYPES.addAll(Arrays.asList(ImageScanType.values()));
		}

		@Override
		public String convertToDatabaseColumn(ScanType attribute) {
			return attribute.getTypeName();
		}

		@Override
		public ScanType convertToEntityAttribute(String dbData) {
			for (ScanType type : TYPES) {
				if (type.getTypeName().equals(dbData)) {
					return type;
				}
			}
			return null;
		}

	}
}
