package com.tracelink.appsec.module.eslint.engine.json;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.gson.Gson;
import com.tracelink.appsec.module.eslint.model.EsLintRuleFixable;
import com.tracelink.appsec.module.eslint.model.EsLintRuleType;

public class MetaTest {

	private Meta meta;
	private Docs docs;

	@BeforeEach
	public void setup() {
		meta = new Meta();
		meta.setType(EsLintRuleType.LAYOUT);
		docs = new Docs();
		meta.setDocs(docs);
		meta.setFixable(EsLintRuleFixable.CODE);
		meta.setSchema("[]");
		meta.setDeprecated(true);
		meta.setReplacedBy("[\"some-rule\"]");
		meta.setMessages(Collections.singletonMap("unexpected", "Do something else"));
	}

	@Test
	public void testGettersAndSetters() {
		Assertions.assertEquals(EsLintRuleType.LAYOUT, meta.getType());
		Assertions.assertEquals(docs, meta.getDocs());
		Assertions.assertEquals(EsLintRuleFixable.CODE, meta.getFixable());
		Assertions.assertEquals("[]", meta.getSchema());
		Assertions.assertTrue(meta.getDeprecated());
		Assertions.assertEquals("[\"some-rule\"]", meta.getReplacedBy());
		Assertions.assertEquals("Do something else", meta.getMessages().get("unexpected"));
	}

	@Test
	public void testToJson() {
		String json = new Gson().toJson(meta);
		Assertions.assertTrue(json.contains("\"schema\":[]"));
		Assertions.assertTrue(json.contains("\"replacedBy\":[\"some-rule\"]"));
	}
}
