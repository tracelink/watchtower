package com.tracelink.appsec.module.regex;

import com.tracelink.appsec.module.regex.designer.RegexRuleDesigner;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.module.regex.service.RegexRuleService;
import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.test.CodeScannerModuleTest;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder;

public class RegexModuleTest extends CodeScannerModuleTest {

	@Override
	protected AbstractCodeScanModule buildScannerModule() {
		return new RegexModule(new RegexRuleDesigner(), new RegexRuleService(null));
	}

	@Override
	protected void configurePluginTester(
			ScannerModuleTestBuilder<CodeScanReport, String> testPlan) {
		testPlan.withMigration("db/regex").withName("Regex").withRuleSupplier(() -> {
			RegexCustomRuleDto rule = new RegexCustomRuleDto();
			rule.setAuthor("author");
			rule.setExternalUrl("http://example.com/regex");
			rule.setFileExtension("");
			rule.setMessage("message");
			rule.setName("RegexRule");
			rule.setPriority(RulePriority.MEDIUM_HIGH);
			rule.setRegexPattern(".*");
			return rule;
		}).withSchemaName("regex_schema_history").withSupportedRuleClass(RegexCustomRuleDto.class);
	}

}
