package com.tracelink.appsec.module.pmd.scanner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.module.pmd.controller.PMDRuleEditControllerTest;
import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.module.pmd.model.PMDProvidedRuleDto;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;
import net.sourceforge.pmd.renderers.EmptyRenderer;

@ExtendWith(MockitoExtension.class)
public class PMDScannerTest {
	@RegisterExtension
	public LogWatchExtension loggerRule = LogWatchExtension.forClass(PMDReport.class);

	private static PMDRuleService ruleService;

	@BeforeAll
	public static void setup() {
		ruleService = new PMDRuleService(null);
	}

	@Test
	public void testFindingCarriesSelectedDefinition() throws Exception {
		Path directory = Files.createTempDirectory("pmd-identity");
		Path source = directory.resolve("Example.java");
		try {
			Files.writeString(source, "class Example { void unsafe() {} }");
			var rule = new PMDCustomRuleDto();
			rule.setId(42L);
			rule.setName("identity-example");
			rule.setParserLanguage("java");
			rule.setRuleClass("net.sourceforge.pmd.lang.rule.xpath.XPathRule");
			rule.setPriority(RulePriority.HIGH);
			rule.setMessage("Unsafe method");
			var property = new PMDPropertyDto();
			property.setName("xpath");
			property.setValue("//MethodDeclaration");
			rule.setProperties(List.of(property));
			RulesetDto selected = new RulesetDto();
			selected.setName("selected");
			selected.setDescription("Identity test");
			selected.setRules(Set.of(rule));
			CodeScanConfig config = new CodeScanConfig();
			config.setRuleset(selected);
			config.setWorkingDirectory(directory);
			PMDScanner scanner = new PMDScanner(ruleService);
			var identity = scanner.getExecutionIdentity(config);
			Assertions.assertTrue(identity.isReusable(), "The bundled PMD runtime must establish complete evidence");
			var captured = com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot
					.capture(selected, List.of(scanner), config).withOutcome(scanner, "RAN");
			Assertions.assertTrue(captured.hasSuccessfulExecution());
			PMDReport report = scanner.scan(config);
			Assertions.assertTrue(report.getErrors().isEmpty());
			Assertions.assertEquals(1, report.getViolations().size());
			Assertions.assertEquals(rule.getExecutionIdentity(), report.getViolations().get(0).getRuleIdentity());
			config.setBenchmarkEnabled(true);
			config.setWorkingDirectory(directory.resolve("other"));
			Assertions.assertEquals(identity, scanner.getExecutionIdentity(config));
			config.setThreads(config.getThreads() + 1);
			Assertions.assertNotEquals(identity, scanner.getExecutionIdentity(config));
			config.setThreads(config.getThreads() - 1);
			property.setValue("//ClassDeclaration");
			Assertions.assertNotEquals(identity, scanner.getExecutionIdentity(config),
					"A same-name XPath edit must invalidate execution evidence");
			property.setValue("//MethodDeclaration[current-dateTime() = current-dateTime()]");
			Assertions.assertFalse(scanner.getExecutionIdentity(config).isReusable(),
					"XPath calls with untracked external/runtime dependencies must rescan");
			property.setValue("//MethodDeclaration[fn:doc#1]");
			Assertions.assertFalse(scanner.getExecutionIdentity(config).isReusable());
			property.setValue("//MethodDeclaration");
			for (String xmlOverride : List.of("xml.catalog.files", "SAXON_INITIALIZER")) {
				String originalOverride = System.getProperty(xmlOverride);
				try {
					System.setProperty(xmlOverride, directory.resolve("private-override").toString());
					Assertions.assertFalse(scanner.getExecutionIdentity(config).isReusable());
				} finally {
					if (originalOverride == null) System.clearProperty(xmlOverride);
					else System.setProperty(xmlOverride, originalOverride);
				}
			}
			Assertions.assertFalse(new PMDScanner(ruleService) {}.getExecutionIdentity(config).isReusable());
			Assertions.assertFalse(new PMDScanner(new PMDRuleService(null) {})
					.getExecutionIdentity(config).isReusable());
			rule.setRuleClass("untracked.extension.Rule");
			Assertions.assertFalse(scanner.getExecutionIdentity(config).isReusable());
			var provided = new PMDProvidedRuleDto();
			provided.setId(43L);
			provided.setName("UnusedLocalVariable");
			provided.setPriority(RulePriority.HIGH);
			selected.setRules(Set.of(provided));
			Assertions.assertTrue(scanner.getExecutionIdentity(config).isReusable(),
					"A selected provided rule must resolve against the captured catalog");
			provided.setName("missing-catalog-rule");
			Assertions.assertFalse(scanner.getExecutionIdentity(config).isReusable());
			Assertions.assertFalse(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(identity)
					.contains(directory.toString()));
		} finally {
			Files.deleteIfExists(source);
			Files.deleteIfExists(directory);
		}
	}

	@Test
	public void testBenchmarkSet() throws Exception {
		Path workingDirectory = Files.createTempDirectory(null);
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("Default");
		ruleset.setDescription("Set of default rules");
		ruleset.setRules(Collections.singleton(PMDRuleEditControllerTest.getPMDRuleDto()));
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);
		config.setWorkingDirectory(workingDirectory);
		config.setBenchmarkEnabled(true);
		PMDReport report = new PMDScanner(ruleService).scan(config);
		Assertions.assertTrue(loggerRule.getMessages().isEmpty());
		report.logRuleBenchmarking();
		List<String> messages = loggerRule.getMessages();
		Assertions.assertEquals(1, messages.size());
		Assertions.assertTrue(messages.get(0).contains("Wall Clock Time"));
	}

	@Test
	public void testWatchtowerPMDConfigDefaults(@org.junit.jupiter.api.io.TempDir Path directory) throws Exception {
		String inputPath = "/input/path/name";
		int threads = 1;

		PMDScanner.WatchtowerPMDConfiguration pmdConfig =
				new PMDScanner.WatchtowerPMDConfiguration(inputPath, threads);

		Assertions.assertTrue(pmdConfig.isFailOnViolation());
		Assertions.assertEquals(java.util.Collections.singletonList(java.nio.file.Paths.get(inputPath)),
				pmdConfig.getInputPathList());
		Assertions.assertEquals(threads, pmdConfig.getThreads());
		pmdConfig.setReportFormat("empty");
		Assertions.assertEquals(EmptyRenderer.class, pmdConfig.createRenderer().getClass());
		Path jaxp = directory.resolve("jaxp.properties");
		String emptyDefaults = PMDExecutionIdentity.jaxpConfiguration(jaxp);
		Files.writeString(jaxp, "jdk.xml.maxXMLNameLimit=1000\njdk.xml.overrideDefaultParser=false\n");
		String configuredDefaults = PMDExecutionIdentity.jaxpConfiguration(jaxp);
		Assertions.assertNotEquals(emptyDefaults, configuredDefaults);
		Files.writeString(jaxp, "# comments and property order do not change settings\n"
				+ "jdk.xml.overrideDefaultParser=false\njdk.xml.maxXMLNameLimit=1000\n");
		Assertions.assertEquals(configuredDefaults, PMDExecutionIdentity.jaxpConfiguration(jaxp));
		Files.writeString(jaxp, "jdk.xml.maxXMLNameLimit=2000\n");
		Assertions.assertNotEquals(configuredDefaults, PMDExecutionIdentity.jaxpConfiguration(jaxp));
		Files.writeString(jaxp, "javax.xml.parsers.DocumentBuilderFactory=private.extension.Parser\n");
		Assertions.assertThrows(java.io.IOException.class, () -> PMDExecutionIdentity.jaxpConfiguration(jaxp));
	}

}
