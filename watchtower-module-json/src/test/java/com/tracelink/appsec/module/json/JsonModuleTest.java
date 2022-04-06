package com.tracelink.appsec.module.json;

import com.tracelink.appsec.module.json.designer.JsonRuleDesigner;
import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.test.ScannerModuleTest;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestOption;

public class JsonModuleTest extends ScannerModuleTest {

	@Override
	protected AbstractCodeScanModule buildScannerModule() {
		return new JsonModule(new JsonRuleDesigner());
	}

	@Override
	protected void configurePluginTester(ScannerModuleTestBuilder testPlan) {
		testPlan.withMigration("db/json").withName("JSON")
				.withRuleSupplier(() -> {
					JsonRuleDto rule = new JsonRuleDto();
					rule.setAuthor("author");
					rule.setExternalUrl("http://someurl");
					rule.setFileExtension("");
					rule.setMessage("Message");
					rule.setName("RuleName");
					rule.setPriority(RulePriority.MEDIUM);
					rule.setQuery("&.*");
					return rule;
				}).withSchemaName("json_schema_history").withSupportedRuleClass(JsonRuleDto.class)
				.andIgnoreTestOption(ScannerModuleTestOption.PROVIDED_RULES);
	}
}
