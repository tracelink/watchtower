package com.tracelink.appsec.watchtower.core.scan.image.entity;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrImageScanTest;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanViolation;

public class ImageScanEntityTests {

	private static final boolean blocking = false;
	private static final RulePriority severity = RulePriority.HIGH;

	private static final long lastReviewedDate = 1000L;
	private static final String error = "error";
	private static final long startDate = 900L;
	private static final ScanStatus status = ScanStatus.DONE;
	private static final long submitDate = 800L;

	private static final String apiLabel = "apiLabel";
	private static final String repositoryName = "imageName";
	private static final String tagName = "tagName";

	public static ImageViolationEntity buildStandardViolation() {
		ImageViolationEntity violation = new ImageViolationEntity();
		violation.setAdvisory(AdvisoryEntityTest.buildStandardAdvisory());
		violation.setBlocking(blocking);
		violation.setSeverity(severity);
		violation.setViolationName(AdvisoryEntityTest.advisoryName);
		violation.setScan(buildStandardScan());
		return violation;
	}

	public static ImageScanEntity buildStandardScan() {
		ImageScanEntity scan = new ImageScanEntity();
		scan.setEndDate(lastReviewedDate);
		scan.setError(error);
		scan.setStartDate(startDate);
		scan.setStatus(status);
		scan.setSubmitDate(submitDate);
		scan.setContainer(buildStandardContainer());
		return scan;
	}

	public static ImageScanContainerEntity buildStandardContainer() {
		ImageScanContainerEntity container = new ImageScanContainerEntity();
		container.setApiLabel(apiLabel);
		container.setRepositoryName(repositoryName);
		container.setLastReviewedDate(lastReviewedDate);
		container.setTagName(tagName);
		return container;
	}

	@Test
	public void testDAO() {
		ImageViolationEntity violation = buildStandardViolation();
		Assertions.assertEquals(blocking, violation.isBlocking());
		Assertions.assertEquals(severity, violation.getSeverity());
		Assertions.assertEquals(AdvisoryEntityTest.advisoryName, violation.getViolationName());
		Assertions.assertNotNull(violation.getAdvisory());
		Assertions.assertNotNull(violation.getScan());

		ImageScanEntity scan = violation.getScan();
		Assertions.assertEquals(lastReviewedDate, scan.getEndDateMillis());
		Assertions.assertEquals(LocalDateTime.ofInstant(Instant.ofEpochMilli(lastReviewedDate),
				ZoneId.systemDefault()), scan.getEndDate());
		Assertions.assertEquals(error, scan.getError());
		Assertions.assertEquals(startDate, scan.getStartDateMillis());
		Assertions.assertEquals(LocalDateTime.ofInstant(Instant.ofEpochMilli(startDate),
				ZoneId.systemDefault()), scan.getStartDate());
		Assertions.assertEquals(status, scan.getStatus());
		Assertions.assertEquals(submitDate, scan.getSubmitDateMillis());
		Assertions.assertEquals(LocalDateTime.ofInstant(Instant.ofEpochMilli(submitDate),
				ZoneId.systemDefault()), scan.getSubmitDate());
		Assertions.assertNotNull(scan.getContainer());

		ImageScanContainerEntity container = scan.getContainer();
		Assertions.assertEquals(apiLabel, container.getApiLabel());
		Assertions.assertEquals(repositoryName, container.getRepositoryName());
		Assertions.assertEquals(lastReviewedDate, container.getLastReviewedDate());
		Assertions.assertEquals(tagName, container.getTagName());
	}

	@Test
	public void testViolationSpecialConstructor() {
		ImageScanViolation sv = new ImageScanViolation();
		sv.setSeverity(RulePriority.HIGH);
		sv.setFindingName("foo");
		AdvisoryEntity advisory = new AdvisoryEntity();
		ImageViolationEntity entity = new ImageViolationEntity(sv, advisory);
		Assertions.assertEquals(advisory, entity.getAdvisory());
		Assertions.assertEquals(RulePriority.HIGH, entity.getSeverity());
		Assertions.assertEquals("foo", entity.getViolationName());
	}

	@Test
	public void testViolationCompares() {
		Assertions.assertEquals(0, buildStandardViolation().compareTo(buildStandardViolation()));
	}

	@Test
	public void testContainerSpecialConstructor() {
		ImageScan scan = EcrImageScanTest.buildStandardEcrImageScan();
		ImageScanContainerEntity entity = new ImageScanContainerEntity(scan);
		Assertions.assertEquals(EcrImageScanTest.API_LABEL, entity.getApiLabel());
		Assertions.assertEquals(EcrImageScanTest.REPOSITORY_NAME, entity.getRepositoryName());
		Assertions.assertEquals(EcrImageScanTest.TAG_NAME, entity.getTagName());
	}
}
