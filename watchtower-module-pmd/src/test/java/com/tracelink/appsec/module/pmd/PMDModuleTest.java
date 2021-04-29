package com.tracelink.appsec.module.pmd;

import java.util.Arrays;

import com.tracelink.appsec.module.pmd.designer.PMDRuleDesigner;
import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.module.pmd.model.PMDRuleDto;
import com.tracelink.appsec.watchtower.core.module.AbstractModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.test.ScannerModuleTest;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder;

public class PMDModuleTest extends ScannerModuleTest {

	@Override
	protected AbstractModule buildScannerModule() {
		return new PMDModule(new PMDRuleDesigner());
	}

	@Override
	protected void configurePluginTester(ScannerModuleTestBuilder testPlan) {
		testPlan.withMigration("db/pmd").withName("PMD").withRuleSupplier(() -> {
			PMDRuleDto rule = new PMDRuleDto();
			rule.setAuthor("author");
			rule.setDescription("description");
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
		}).withSchemaName("pmd_schema_history").withSupportedRuleClass(PMDRuleDto.class);
	}

}
