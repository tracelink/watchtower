package com.tracelink.appsec.watchtower.core.scan;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;

public interface ScanType extends Serializable {
	public String getTypeName();

	public String getDisplayName();

	@Converter
	public static class ScanTypeConverter implements AttributeConverter<ScanType, String> {
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
