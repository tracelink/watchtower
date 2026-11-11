package com.tracelink.appsec.module.pmd.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.module.pmd.rules.pom.RestrictNodesUnderProject;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

/**
 * Real fixture-based regression test: runs {@link PMDScanner} end to end against a real source
 * file, a real custom rule ({@link RestrictNodesUnderProject}, the only custom rule this project
 * bundles that exercises the DOM/XPath-driven POM rule base class), and asserts on an actual
 * detected violation.
 *
 * <p>
 * This complements the Java XPath fixture in {@code PMDScannerTest} and catches a PMD version
 * upgrade that silently stops detecting real XML violations. See the PMD 6 → 7 upgrade notes in
 * {@code UPGRADE_PLAN.md} (Tier 4a) for the
 * full rationale — in particular the open question of whether PMD 7's move from Jaxen to Saxon
 * for XPath execution changed {@code XmlNode.findChildNodesWithXPath}'s behavior, which
 * {@code BasicPomRule} (the superclass of {@link RestrictNodesUnderProject}) depends on.
 *
 * @author Claude
 */
public class PMDScannerFixtureViolationTest {

	@Test
	public void testRestrictNodesUnderProjectDetectsRealViolationInRealPom() throws Exception {
		Path workingDirectory = Files.createTempDirectory(null);
		Path pomFile = workingDirectory.resolve("pom.xml");
		Files.write(pomFile, ("<project>\n"
				+ "  <modelVersion>4.0.0</modelVersion>\n"
				+ "  <disallowedTag>some-value</disallowedTag>\n"
				+ "</project>\n").getBytes(StandardCharsets.UTF_8));

		PMDPropertyDto subNodesProperty = new PMDPropertyDto();
		subNodesProperty.setName("subNodes");
		subNodesProperty.setValue("modelVersion");

		PMDCustomRuleDto ruleDto = new PMDCustomRuleDto();
		ruleDto.setName("RestrictTestRule");
		ruleDto.setMessage("Disallowed node directly under <project>");
		ruleDto.setPriority(RulePriority.HIGH);
		ruleDto.setParserLanguage("xml");
		ruleDto.setRuleClass(RestrictNodesUnderProject.class.getName());
		ruleDto.setProperties(Arrays.asList(subNodesProperty));

		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("Fixture Ruleset");
		ruleset.setDescription("Fixture ruleset for a real end-to-end violation check");
		ruleset.setDesignation(RulesetDesignation.PRIMARY);
		ruleset.setRules(Collections.singleton(ruleDto));

		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);
		config.setWorkingDirectory(workingDirectory);
		config.setThreads(1);

		PMDScanner scanner = new PMDScanner(new PMDRuleService(null));
		assertTrue(scanner.getExecutionIdentity(config).isReusable(),
				"The bundled XML parser and POM rule must establish complete runtime evidence");
		PMDReport report = scanner.scan(config);

		assertNotNull(report, "Scan must produce a report, not fail outright");
		assertTrue(report.getErrors().isEmpty(),
				"Scan must not report configuration/processing errors: " + report.getErrors());
		assertEquals(1, report.getViolations().size(),
				"Expected exactly one violation for the disallowed <disallowedTag> element under <project>");

		CodeScanViolation violation = report.getViolations().get(0);
		assertEquals("RestrictTestRule", violation.getViolationName());
		assertEquals(3, violation.getLineNum(),
				"Violation must be reported on the line of the disallowed element");
	}

}
