package com.tracelink.appsec.watchtower.core.rest.scan.image.result;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;

public class ImageScanResultTest {


	private static final String apiLabel = "APILABEL";
	private static final LocalDateTime endDate = LocalDateTime.of(2022, 1, 1, 1, 0);
	private static final String errorMessage = "ERROR";
	private static final long id = 0;
	private static final String imageName = "IMAGENAME";
	private static final String status = ScanStatus.DONE.getDisplayName();
	private static final LocalDateTime submitDate = LocalDateTime.of(2022, 1, 1, 0, 0);
	private static final String tagName = "TAG";

	public static ImageScanResult buildStandardResult() {
		ImageScanResult result = new ImageScanResult();
		result.setApiLabel(apiLabel);
		result.setEndDate(endDate);
		result.setErrorMessage(errorMessage);
		result.setId(id);
		result.setImageName(imageName);
		result.setStatus(status);
		result.setSubmitDate(submitDate);
		result.setTagName(tagName);
		result.setViolations(
				Arrays.asList(ImageScanResultViolationTest.buildStandardResultViolation()));
		return result;
	}

	@Test
	public void testDAO() {
		ImageScanResult result = buildStandardResult();
		Assertions.assertEquals(apiLabel, result.getApiLabel());
		Assertions.assertEquals(endDate, result.getEndDate());
		Assertions.assertEquals(endDate.toInstant(ZoneOffset.UTC).toEpochMilli(),
				result.getEndDateMillis());
		Assertions.assertEquals(errorMessage, result.getErrorMessage());
		Assertions.assertEquals(id, result.getId());
		Assertions.assertEquals(imageName, result.getImageName());
		Assertions.assertEquals(status, result.getStatus());
		Assertions.assertEquals(submitDate, result.getSubmitDate());
		Assertions.assertEquals(submitDate.toInstant(ZoneOffset.UTC).toEpochMilli(),
				result.getSubmitDateMillis());
		Assertions.assertEquals(tagName, result.getTagName());
		Assertions.assertEquals(1, result.getViolations().size());

	}

}
