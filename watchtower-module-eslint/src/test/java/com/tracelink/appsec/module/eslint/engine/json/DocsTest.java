package com.tracelink.appsec.module.eslint.engine.json;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class DocsTest {

	@Test
	public void testGettersAndSetters() {
		Docs docs = new Docs();
		docs.setDescription("Some description");
		docs.setCategory("Rule Category");
		docs.setRecommended(false);
		docs.setUrl("https://example.com");
		docs.setSuggestion(true);

		Assertions.assertEquals("Some description", docs.getDescription());
		Assertions.assertEquals("Rule Category", docs.getCategory());
		Assertions.assertFalse(docs.getRecommended());
		Assertions.assertEquals("https://example.com", docs.getUrl());
		Assertions.assertTrue(docs.getSuggestion());
	}

}
