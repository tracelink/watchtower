package com.tracelink.appsec.watchtower.core.scan.image.entity;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AdvisoryEntityTest {

	public static final String advisoryName = "Advisory";
	public static final String description = "Description";
	public static final String packageName = "PKG";
	public static final String score = "9.4";
	public static final String uri = "http://localhost";
	public static final String vector = "VECTOR";

	public static AdvisoryEntity buildStandardAdvisory() {
		AdvisoryEntity advisory = new AdvisoryEntity();
		advisory.setAdvisoryName(advisoryName);
		advisory.setDescription(description);
		advisory.setPackageName(packageName);
		advisory.setScore(score);
		advisory.setUri(uri);
		advisory.setVector(vector);
		return advisory;
	}

	@Test
	public void testDAO() {
		AdvisoryEntity advisory = buildStandardAdvisory();
		Assertions.assertEquals(advisoryName, advisory.getAdvisoryName());
		Assertions.assertEquals(description, advisory.getDescription());
		Assertions.assertEquals(packageName, advisory.getPackageName());
		Assertions.assertEquals(score, advisory.getScore());
		Assertions.assertEquals(uri, advisory.getUri());
		Assertions.assertEquals(vector, advisory.getVector());
	}
}
