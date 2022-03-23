package com.tracelink.appsec.module.pmd.scanner;


import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.module.pmd.controller.PMDRuleEditControllerTest;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.scm.ScmScanConfig;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;

import net.sourceforge.pmd.renderers.EmptyRenderer;
import net.sourceforge.pmd.renderers.Renderer;

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
	public void testBenchmarkSet() throws Exception {
		Path workingDirectory = Files.createTempDirectory(null);
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("Default");
		ruleset.setDescription("Set of default rules");
		ruleset.setRules(Collections.singleton(PMDRuleEditControllerTest.getPMDRuleDto()));
		ScmScanConfig config = new ScmScanConfig();
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
	public void testPMDRenderer() {
		PMDScanner.WatchtowerPMDConfiguration pmdConfig =
				new PMDScanner.WatchtowerPMDConfiguration("", "", 1);
		pmdConfig.setReportFormat("empty");
		Renderer renderer = pmdConfig.createRenderer();
		Assertions.assertEquals(EmptyRenderer.class.getName(), renderer.getClass().getName());
	}

	@Test
	public void testWatchtowerPMDConfigRendererAndDefaults() throws Exception {
		String inputPath = "/input/path/name";
		String ruleSets = "ruleset.xml";
		int threads = 1;

		PMDScanner.WatchtowerPMDConfiguration pmdConfig =
				new PMDScanner.WatchtowerPMDConfiguration(inputPath, ruleSets,
						threads);
		Renderer renderer = new PMDRenderer();
		pmdConfig.setRenderer(renderer);
		Assertions.assertEquals(renderer, pmdConfig.getRenderer());
		Assertions.assertEquals(renderer, pmdConfig.createRenderer());
		Assertions.assertTrue(pmdConfig.isFailOnViolation());
		Assertions.assertEquals(inputPath, pmdConfig.getInputPaths());
		Assertions.assertEquals(ruleSets, pmdConfig.getRuleSets());
		Assertions.assertEquals(threads, pmdConfig.getThreads());
	}

}
