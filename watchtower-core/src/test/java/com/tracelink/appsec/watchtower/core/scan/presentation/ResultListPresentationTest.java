package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import org.junit.jupiter.api.Test;

class ResultListPresentationTest {

	@Test
	void pullRequestMissingCompletionDateDoesNotBecomeUnixEpoch() {
		PRScanResult result = new PRScanResult();
		assertEquals(0L, result.getDateMillis());
	}

	@Test
	void allResultTypesExposeSharedStatusPresentationWithoutChangingJson() throws Exception {
		PRScanResult pullRequest = new PRScanResult();
		pullRequest.setStatusPresentation(StatusPresentationModel.from(ScanStatus.FAILED));
		UploadScanResult upload = new UploadScanResult();
		upload.setStatus(ScanStatus.IN_PROGRESS.getDisplayName());
		ImageScanResult image = new ImageScanResult();
		image.setStatus(ScanStatus.DONE.getDisplayName());

		assertEquals("Failed", pullRequest.getStatusPresentation().getLabel());
		assertEquals("Running", upload.getStatusPresentation().getLabel());
		assertEquals("Finished", image.getStatusPresentation().getLabel());

		ObjectMapper mapper = new ObjectMapper();
		assertEquals(false, mapper.writeValueAsString(pullRequest).contains("statusPresentation"));
		assertEquals(false, mapper.writeValueAsString(upload).contains("statusPresentation"));
		assertEquals(false, mapper.writeValueAsString(image).contains("statusPresentation"));
	}

	@Test
	void imageResultsShowDurationLikeUploads() throws Exception {
		ImageScanResult image = new ImageScanResult();
		assertEquals("Not finished", image.getDurationText());
		image.setSubmitDate(java.time.LocalDateTime.of(2024, 8, 9, 1, 45, 7));
		image.setEndDate(java.time.LocalDateTime.of(2024, 8, 9, 1, 46, 12));
		assertEquals(HomeActivityItem.formatDuration(image.getSubmitDateMillis(), image.getEndDateMillis()),
				image.getDurationText());
		assertEquals(false, new ObjectMapper().findAndRegisterModules().writeValueAsString(image).contains("durationText"));
	}
}
