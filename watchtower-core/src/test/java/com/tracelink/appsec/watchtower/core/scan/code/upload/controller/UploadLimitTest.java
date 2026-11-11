package com.tracelink.appsec.watchtower.core.scan.code.upload.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class UploadLimitTest {

	private static final long MIB_250 = 262_144_000L;

	@Test
	void showsTheEffectiveLimitAsAShortChipAndTheExactLimitsOnHover() {
		UploadLimit limit = new UploadLimit(MIB_250, MIB_250);

		assertEquals("Up to 250 MB", limit.summary());
		assertEquals("File limit 250 MiB (262,144,000 bytes). The whole request, form fields included, "
				+ "must also stay under 250 MiB.", limit.detail());
	}

	@Test
	void theSmallerOfTheFileAndRequestLimitsApplies() {
		assertEquals("Up to 100 MB", new UploadLimit(MIB_250, 104_857_600L).summary());
		assertEquals("Up to 100 MB", new UploadLimit(104_857_600L, -1).summary());
	}

	@Test
	void unlimitedUploadsSaySo() {
		UploadLimit limit = new UploadLimit(-1, -1);

		assertEquals("No size limit", limit.summary());
		assertEquals("The server sets no upload size limit.", limit.detail());
	}
}
