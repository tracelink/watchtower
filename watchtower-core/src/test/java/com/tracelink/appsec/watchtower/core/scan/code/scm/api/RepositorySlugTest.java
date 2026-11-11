package com.tracelink.appsec.watchtower.core.scan.code.scm.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class RepositorySlugTest {

	@ParameterizedTest
	@CsvSource({"payments-api, payments-api", "Payments-API, payments-api",
			"' Payments API ', payments-api", "Access-Review-Scripts, access-review-scripts",
			"my.repo_2, my.repo_2", "'A & B!', a-b"})
	public void everySpellingOfARepositoryIsItsSlug(String name, String slug) {
		Assertions.assertEquals(slug, RepositorySlug.of(name));
		Assertions.assertEquals(slug, RepositorySlug.of(slug), "a slug is unchanged");
	}

	@Test
	public void nullStaysNull() {
		Assertions.assertNull(RepositorySlug.of(null));
	}
}
