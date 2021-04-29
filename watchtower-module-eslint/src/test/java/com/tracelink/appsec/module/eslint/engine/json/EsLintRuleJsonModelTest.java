package com.tracelink.appsec.module.eslint.engine.json;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class EsLintRuleJsonModelTest {

	@Test
	public void testGettersAndSetters() {
		EsLintRuleJsonModel ruleJsonModel = new EsLintRuleJsonModel();
		Meta meta = new Meta();
		ruleJsonModel.setMeta(meta);
		ruleJsonModel.setCreateFunction("create(context) {}");

		Assertions.assertEquals(meta, ruleJsonModel.getMeta());
		Assertions.assertEquals("create(context) {}", ruleJsonModel.getCreateFunction());
	}
}
