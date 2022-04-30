package com.tracelink.appsec.watchtower.core.scan.image;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanError;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanReport;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanViolation;

public class ImageScanReportTests {

	public static final String description = "description";
	public static final String findingName = "findingName";
	public static final String packageName = "packageName";
	public static final String score = "score";
	public static final RulePriority severity = RulePriority.HIGH;
	public static final String uri = "uri";
	public static final String vector = "vector";
	public static final String message = "message";

	public static ImageScanViolation buildStandardImageScanViolation() {
		ImageScanViolation isv = new ImageScanViolation();
		isv.setDescription(description);
		isv.setFindingName(findingName);
		isv.setPackageName(packageName);
		isv.setScore(score);
		isv.setSeverity(severity);
		isv.setUri(uri);
		isv.setVector(vector);
		return isv;
	}

	public static ImageScanError buildStandardError() {
		return new ImageScanError(message);
	}

	public static ImageScanReport buildStandardReport() {
		ImageScanReport report = new ImageScanReport();
		report.addError(buildStandardError());
		report.addViolation(buildStandardImageScanViolation());
		return report;
	}

	@Test
	public void testDAO() {
		ImageScanReport report = buildStandardReport();
		Assertions.assertEquals(1, report.getViolations().size());
		Assertions.assertEquals(1, report.getErrors().size());

		ImageScanError error = report.getErrors().get(0);
		Assertions.assertEquals(message, error.getErrorMessage());

		ImageScanViolation violation = report.getViolations().get(0);
		Assertions.assertEquals(description, violation.getDescription());
		Assertions.assertEquals(findingName, violation.getFindingName());
		Assertions.assertEquals(packageName, violation.getPackageName());
		Assertions.assertEquals(score, violation.getScore());
		Assertions.assertEquals(severity, violation.getSeverity());
		Assertions.assertEquals(uri, violation.getUri());
		Assertions.assertEquals(vector, violation.getVector());
	}
}
