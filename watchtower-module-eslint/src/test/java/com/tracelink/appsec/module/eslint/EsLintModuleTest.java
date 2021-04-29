package com.tracelink.appsec.module.eslint;

import java.util.Collections;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;

import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDto;
import com.tracelink.appsec.watchtower.core.module.AbstractModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.test.ScannerModuleTest;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder.TestScanConfiguration;

public class EsLintModuleTest extends ScannerModuleTest {

	@Override
	protected AbstractModule buildScannerModule() {
		return new EsLintModule();
	}

	@Override
	protected void configurePluginTester(ScannerModuleTestBuilder testPlan) {
		EsLintRuleDto rule = new EsLintRuleDto();
		rule.setAuthor("author");
		rule.setExternalUrl("https://example.com");
		rule.setMessage("Message");
		rule.setName("no-console");
		rule.setPriority(RulePriority.MEDIUM);
		rule.setCore(true);

		testPlan.withMigration("db/eslint").withName("ESLint")
				.withRuleSupplier(() -> {
					EsLintRuleDto customRule = new EsLintRuleDto();
					customRule.setAuthor("author");
					customRule.setExternalUrl("https://example.com");
					customRule.setMessage("Message");
					customRule.setName("rule-name");
					customRule.setPriority(RulePriority.MEDIUM);
					customRule.setCore(false);
					EsLintMessageDto messageDto = new EsLintMessageDto();
					messageDto.setKey("myMessage");
					messageDto.setValue("Some helpful message");
					customRule.setMessages(Collections.singletonList(messageDto));
					customRule.setCreateFunction("create(context) {\n"
							+ "\treturn {\n"
							+ "\t\tBinaryExpression(node) {\n"
							+ "\t\t\tconst badOperator = node.operator === \"==\" || node.operator === \"!=\";\n"
							+ "\t\t\tif (node.right.type === \"Literal\" && node.right.raw === \"null\"\n"
							+ "\t\t\t\t\t&& badOperator || node.left.type === \"Literal\"\n"
							+ "\t\t\t\t\t&& node.left.raw === \"null\" && badOperator) {\n"
							+ "\t\t\t\tcontext.report({ node, messageId: \"myMessage\" });\n"
							+ "\t\t\t}\n"
							+ "\t\t}\n"
							+ "\t};\n"
							+ "}");
					return customRule;
				}).withSchemaName("eslint_schema_history")
				.withSupportedRuleClass(EsLintRuleDto.class)
				.withTestScanConfigurationBuilder(
						new TestScanConfiguration()
								.withTargetResourceFile("/scan/simple.js")
								.withRuleset(new RulesetDto() {
									{
										setName("testRuleset");
										setDescription("description");
										setRules(Collections.singleton(rule));
									}
								})
								.withAssertClause(report -> {
									MatcherAssert.assertThat(report.getErrors(), Matchers.hasSize(0));
									MatcherAssert.assertThat(report.getViolations(), Matchers.hasSize(1));
								}));
	}
}
