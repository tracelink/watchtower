package com.tracelink.appsec.watchtower.core.scan.image.result;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResultViolation;

public class ImageScanResultViolationTest {


	private static final String description = "DESCRIPTION";
	private static final String packageName = "PKGNAME";
	private static final String score = "9.3";
	private static final String severity = "HIGH";
	private static final String uri = "http://uri";
	private static final String vector = "VECTOR";
	private static final String violationName = "VIONAME";

	public static ImageScanResultViolation buildStandardResultViolation() {
		ImageScanResultViolation violation = new ImageScanResultViolation();
		violation.setDescription(description);
		violation.setPackageName(packageName);
		violation.setScore(score);
		violation.setSeverity(severity);
		violation.setUri(uri);
		violation.setVector(vector);
		violation.setViolationName(violationName);
		return violation;
	}

	@Test
	public void testDAO() {
		ImageScanResultViolation violation = buildStandardResultViolation();

		Assertions.assertEquals(description, violation.getDescription());
		Assertions.assertEquals(packageName, violation.getPackageName());
		Assertions.assertEquals(score, violation.getScore());
		Assertions.assertEquals(severity, violation.getSeverity());
		Assertions.assertEquals(uri, violation.getUri());
		Assertions.assertEquals(vector, violation.getVector());
		Assertions.assertEquals(violationName, violation.getViolationName());
	}
}
