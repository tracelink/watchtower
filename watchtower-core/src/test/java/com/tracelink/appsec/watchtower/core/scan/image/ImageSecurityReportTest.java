package com.tracelink.appsec.watchtower.core.scan.image;

import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrImageScanTest;

public class ImageSecurityReportTest {

	private static final String findingName = "Finding";
	private static final String description = "Description";
	private static final String packageName = "Package";
	private static final String packageVersion = "1.0.0";
	private static final String score = "9.6";
	private static final RulePriority severity = RulePriority.HIGH;
	private static final String uri = "URI";
	private static final String vector = "VECTOR";

	public static ImageSecurityReport buildStandardReport(ImageScan image) {
		ImageSecurityReport report = new ImageSecurityReport(image);
		report.setFindings(Arrays.asList(buildStandardFinding()));
		return report;
	}

	public static ImageSecurityFinding buildStandardFinding() {
		ImageSecurityFinding finding = new ImageSecurityFinding();
		finding.setFindingName(findingName);
		finding.setDescription(description);
		finding.setPackageName(packageName);
		finding.setPackageVersion(packageVersion);
		finding.setScore(score);
		finding.setSeverity(severity);
		finding.setUri(uri);
		finding.setVector(vector);
		return finding;
	}

	@Test
	public void testDAO() {
		EcrImageScan image = EcrImageScanTest.buildStandardEcrImageScan();
		ImageSecurityReport report = buildStandardReport(image);
		Assertions.assertEquals(1, report.getFindings().size());
		ImageSecurityFinding finding = report.getFindings().get(0);
		Assertions.assertEquals(findingName, finding.getFindingName());
		Assertions.assertEquals(description, finding.getDescription());
		Assertions.assertEquals(packageName, finding.getPackageName());
		Assertions.assertEquals(packageVersion, finding.getPackageVersion());
		Assertions.assertEquals(score, finding.getScore());
		Assertions.assertEquals(severity, finding.getSeverity());
		Assertions.assertEquals(uri, finding.getUri());
		Assertions.assertEquals(vector, finding.getVector());
	}
}
