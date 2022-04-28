package com.tracelink.appsec.watchtower.core.scan.image.api.ecr;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class EcrImageScanTest {
	public static final String API_LABEL = "api";
	public static final String REGISTRY_NAME = "registry";
	public static final String REPOSITORY_NAME = "repository";
	public static final String TAG_NAME = "tag";

	public static EcrImageScan buildStandardEcrImageScan() {
		EcrImageScan scan = new EcrImageScan(API_LABEL);
		scan.setRegistry(REGISTRY_NAME);
		scan.setRepository(REPOSITORY_NAME);
		scan.setTag(TAG_NAME);
		return scan;
	}

	@Test
	public void testDAO() {
		EcrImageScan scan = buildStandardEcrImageScan();
		Assertions.assertEquals(API_LABEL, scan.getApiLabel());
		Assertions.assertEquals(REGISTRY_NAME, scan.getRegistry());
		Assertions.assertEquals(REPOSITORY_NAME, scan.getRepository());
		Assertions.assertEquals(TAG_NAME, scan.getTag());
	}
}
