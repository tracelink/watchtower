package com.tracelink.appsec.watchtower.core.scan;

import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

/**
 * Represents the type of a Watchtower scan and provides a method to get a display name for the UI.
 *
 * @author csmith
 */
public interface ScanType extends Serializable {

	String getTypeName();

	String getDisplayName();

	@Converter
	class ScanTypeConverter implements AttributeConverter<ScanType, String> {

		private static final List<ScanType> types = new ArrayList<>();

		public ScanTypeConverter() {
			types.addAll(Arrays.asList(CodeScanType.values()));
			types.addAll(Arrays.asList(ImageScanType.values()));
		}

		@Override
		public String convertToDatabaseColumn(ScanType attribute) {
			return attribute.getTypeName();
		}

		@Override
		public ScanType convertToEntityAttribute(String dbData) {
			for (ScanType type : types) {
				if (type.getTypeName().equals(dbData)) {
					return type;
				}
			}
			return null;
		}

	}
}
