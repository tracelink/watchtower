package com.tracelink.appsec.module.advisory;

import com.tracelink.appsec.module.advisory.designer.AdvisoryRuleDesigner;
import com.tracelink.appsec.module.advisory.model.AdvisoryRuleDto;
import com.tracelink.appsec.watchtower.core.module.AbstractImageScanModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityFinding;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;
import com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanReport;
import com.tracelink.appsec.watchtower.test.ImageScannerModuleTest;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestOption;
import com.tracelink.appsec.watchtower.test.TestScanConfiguration;
import java.util.Arrays;
import java.util.HashSet;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeAll;

public class AdvisoryModuleTest extends ImageScannerModuleTest {

	private static AdvisoryRuleDesigner designer;

	@BeforeAll
	public static void init() {
		designer = new AdvisoryRuleDesigner();
	}

	@Override
	protected AbstractImageScanModule buildScannerModule() {
		return new AdvisoryModule(designer);
	}

	private AdvisoryRuleDto makeRule() {
		AdvisoryRuleDto rule = new AdvisoryRuleDto();
		rule.setAuthor("author");
		rule.setExternalUrl("http://someurl");
		rule.setMessage("Message");
		rule.setName("CVE-2022-1000");
		rule.setPriority(RulePriority.HIGH);
		return rule;
	}

	@Override
	protected void configurePluginTester(
			ScannerModuleTestBuilder<ImageScanReport, ImageSecurityReport> testPlan) {
		ImageSecurityFinding finding = new ImageSecurityFinding();
		finding.setDescription("findingDescription");
		finding.setFindingName("CVE-2022-1000");
		finding.setPackageName("foobar");
		finding.setScore("10.0");
		finding.setSeverity(RulePriority.HIGH);
		finding.setUri("url");
		finding.setVector("A:B:C");

		ImageSecurityFinding finding2 = new ImageSecurityFinding();
		finding2.setDescription("findingDescription");
		finding2.setFindingName("CVE-2022-2000");
		finding2.setPackageName("foobar");
		finding2.setScore("10.0");
		finding2.setSeverity(RulePriority.HIGH);
		finding2.setUri("url");
		finding2.setVector("A:B:C");

		ImageSecurityReport scannerTarget = new ImageSecurityReport(new EcrImageScan("foo"));
		scannerTarget.setFindings(Arrays.asList(finding, finding2));

		testPlan.withName("Advisory").withSchemaName("advisory_schema_history")
				.withMigration("db/advisory").withSupportedRuleClass(AdvisoryRuleDto.class)
				.withRuleSupplier(() -> makeRule()).withTestScanConfigurationBuilder(
				new TestScanConfiguration<ImageScanReport, ImageSecurityReport>()
						.withRuleset(new RulesetDto() {
							{
								setName("testRuleset");
								setDescription("description");
								setRules(new HashSet<>(Arrays.asList(makeRule())));
							}
						})
						.withScannerTarget(scannerTarget)
						.withAssertClause((report) -> {
							MatcherAssert.assertThat(report.getViolations(),
									Matchers.hasSize(1));
						}))
				.andIgnoreTestOption(ScannerModuleTestOption.PROVIDED_RULES);
	}

}
