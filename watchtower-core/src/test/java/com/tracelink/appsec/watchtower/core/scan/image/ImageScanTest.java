package com.tracelink.appsec.watchtower.core.scan.image;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ImageScanTest {
	public static final String API_LABEL = "api";
	public static final String IMAGE_NAME = "image";
	public static final long SUBMIT_TIME = 10000L;
	public static final String TAG_NAME = "tag";

	public static ImageScan buildStandardImageScan() {
		ImageScan scan = new ImageScan();
		scan.setApiLabel(API_LABEL);
		scan.setImageName(IMAGE_NAME);
		scan.setSubmitTime(SUBMIT_TIME);
		scan.setTagName(TAG_NAME);
		return scan;
	}

	@Test
	public void testDAO() {
		ImageScan scan = buildStandardImageScan();
		Assertions.assertEquals(API_LABEL, scan.getApiLabel());
		Assertions.assertEquals(IMAGE_NAME, scan.getImageName());
		Assertions.assertEquals(SUBMIT_TIME, scan.getSubmitTime());
		Assertions.assertEquals(TAG_NAME, scan.getTagName());
	}
}
