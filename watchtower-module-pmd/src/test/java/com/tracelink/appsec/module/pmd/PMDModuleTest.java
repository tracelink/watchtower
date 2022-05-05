package com.tracelink.appsec.module.pmd;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;

import com.tracelink.appsec.module.pmd.designer.PMDRuleDesigner;
import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.test.CodeScannerModuleTest;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder;

public class PMDModuleTest extends CodeScannerModuleTest {

	private static PMDRuleService ruleService;

	@BeforeAll
	public static void setup() {
		ruleService = new PMDRuleService(null);
	}

	@Override
	protected AbstractCodeScanModule buildScannerModule() {
		return new PMDModule(new PMDRuleDesigner(), ruleService);
	}

	@Override
	protected void configurePluginTester(
			ScannerModuleTestBuilder<CodeScanReport, String> testPlan) {
		testPlan.withMigration("db/pmd").withName("PMD").withRuleSupplier(() -> {
			PMDCustomRuleDto rule = new PMDCustomRuleDto();
			rule.setAuthor("author");
			rule.setExternalUrl("http://example.com/pmd");
			rule.setMessage("message");
			rule.setName("Name");
			rule.setParserLanguage("Java");
			rule.setPriority(RulePriority.MEDIUM_HIGH);
			PMDPropertyDto prop = new PMDPropertyDto();
			prop.setName("xpath");
			prop.setValue("propValue");
			rule.setProperties(Arrays.asList(prop));
			rule.setRuleClass("net.sourceforge.pmd.lang.rule.XPathRule");
			return rule;
		}).withSchemaName("pmd_schema_history").withSupportedRuleClass(PMDCustomRuleDto.class);
	}

}
