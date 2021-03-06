package com.tracelink.appsec.module.eslint;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeAll;

import com.tracelink.appsec.module.eslint.designer.EsLintRuleDesigner;
import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.module.eslint.model.EsLintProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.test.CodeScannerModuleTest;
import com.tracelink.appsec.watchtower.test.ScannerModuleTestBuilder;
import com.tracelink.appsec.watchtower.test.TestScanConfiguration;

public class EsLintModuleTest extends CodeScannerModuleTest {

	private static LinterEngine engine;
	private static EsLintRuleDesigner designer;

	@BeforeAll
	public static void init() {
		engine = new LinterEngine();
		designer = new EsLintRuleDesigner(engine);
	}

	@Override
	protected AbstractCodeScanModule buildScannerModule() {
		return new EsLintModule(engine, designer);
	}

	@Override
	protected void configurePluginTester(
			ScannerModuleTestBuilder<CodeScanReport, String> testPlan) {
		Supplier<RuleDto> ruleSupplier = () -> {
			EsLintCustomRuleDto customRule = new EsLintCustomRuleDto();
			customRule.setAuthor("author");
			customRule.setExternalUrl("https://example.com");
			customRule.setMessage("Message");
			customRule.setName("rule-name");
			customRule.setPriority(RulePriority.MEDIUM);
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
		};
		EsLintProvidedRuleDto providedRule = engine.getCoreRules().get("no-console");

		testPlan.withMigration("db/eslint").withName("ESLint")
				.withRuleSupplier(ruleSupplier).withSchemaName("eslint_schema_history")
				.withSupportedRuleClass(EsLintCustomRuleDto.class)
				.withTestScanConfigurationBuilder(
						new TestScanConfiguration<CodeScanReport, String>()
								.withScannerTarget("/scan/simple.js")
								.withRuleset(new RulesetDto() {
									{
										setName("testRuleset");
										setDescription("description");
										setRules(new HashSet<>(
												Arrays.asList(ruleSupplier.get(), providedRule)));
									}
								})
								.withAssertClause(report -> {
									MatcherAssert.assertThat(
											report.getErrors().stream()
													.map(CodeScanError::getErrorMessage)
													.collect(Collectors.joining()),
											report.getErrors(),
											Matchers.hasSize(0));
									MatcherAssert.assertThat(report.getViolations(),
											Matchers.hasSize(1));
								}));
	}
}
