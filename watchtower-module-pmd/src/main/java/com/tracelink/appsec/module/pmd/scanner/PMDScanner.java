package com.tracelink.appsec.module.pmd.scanner;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

import com.tracelink.appsec.module.pmd.model.PMDProvidedRuleDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDRuleDto;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.rule.RuleException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity;

import net.sourceforge.pmd.PMDConfiguration;
import net.sourceforge.pmd.PmdAnalysis;
import net.sourceforge.pmd.benchmark.TimeTracker;
import net.sourceforge.pmd.benchmark.TimingReport;
import net.sourceforge.pmd.lang.rule.Rule;
import net.sourceforge.pmd.lang.rule.RulePriority;
import net.sourceforge.pmd.lang.rule.RuleSet;

/**
 * {@link ICodeScanner} for PMD. Manages the PMD lifecycle and reporting
 *
 * @author csmith, mcool
 */
public class PMDScanner implements ICodeScanner {
	public static final Logger LOG = LoggerFactory.getLogger(PMDScanner.class);
	public static final String DEFAULT_PMD_RULES =
			"rules/security/sec-deserialization.xml,rules/security/sec-xxe.xml";
	private PMDRuleService ruleService;

	public PMDScanner(PMDRuleService ruleService) {
		this.ruleService = ruleService;
	}

	@Override
	public EngineExecutionIdentity getExecutionIdentity(CodeScanConfig config) {
		return PMDExecutionIdentity.capture(this, ruleService, config);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PMDReport scan(CodeScanConfig config) {
		Map<String, RuleExecutionIdentity> identities = config.getRuleset().getAllRules().stream()
				.filter(PMDRuleDto.class::isInstance)
				.collect(Collectors.toMap(RuleDto::getName, RuleDto::getExecutionIdentity));
		RuleSet ruleset;
		try {
			ruleset = buildRuleSet(config.getRuleset());
		} catch (RulesetException e) {
			LOG.error("Exception building ruleset", e);
			return null;
		}

		// Create configuration
		WatchtowerPMDConfiguration pmdConfig =
				new WatchtowerPMDConfiguration(config.getWorkingDirectory().toString(),
						config.getThreads());
		PMDRenderer renderer = new PMDRenderer();
		// Perform scan
		TimingReport timing;
		if (config.isBenchmarkEnabled()) {
			TimeTracker.startGlobalTracking();
		}

		try (PmdAnalysis pmd = PmdAnalysis.create(pmdConfig)) {
			pmd.addRuleSet(ruleset);
			pmd.addRenderer(renderer);
			pmd.performAnalysis();
		}

		if (config.isBenchmarkEnabled()) {
			timing = TimeTracker.stopGlobalTracking();
			renderer.addTimingReport(timing);
		}
		PMDReport report = renderer.createReport();
		report.getViolations().forEach(violation -> violation.setRuleIdentity(
				identities.getOrDefault(violation.getViolationName(),
						RuleExecutionIdentity.unmanaged("pmd", violation.getViolationName()))));
		return report;
	}

	/**
	 * Builds a {@link RuleSet} directly from the given {@link RulesetDto}'s rules. Unlike PMD 6,
	 * PMD 7's {@link PmdAnalysis#addRuleSet(RuleSet)} accepts a {@link RuleSet} object directly,
	 * so there is no need to serialize rules out to a temporary ruleset XML file and reload them
	 * by path, as this module previously did via {@code RuleSetWriter}.
	 *
	 * @param dto the rules to build into a {@link RuleSet}
	 * @return the built {@link RuleSet}
	 * @throws RulesetException if a rule could not be constructed
	 */
	private RuleSet buildRuleSet(RulesetDto dto) throws RulesetException {
		List<Rule> rules = new ArrayList<Rule>();
		try {
			for (RuleDto ruleDto : dto.getAllRules()) {
				if (ruleDto instanceof PMDRuleDto) {
					rules.add(ruleService.makeRuleFromDto(ruleDto));
				}
			}
		} catch (RuleNotFoundException | RuleException e) {
			throw new RulesetException("Error while creating ruleset: " + e.getMessage());
		}

		return RuleSet.create(dto.getName(), dto.getDescription(), "watchtower-ruleset",
				new ArrayList<>(), new ArrayList<>(), rules);
	}

	/**
	 * Mapping object from {@code PMDConfiguration} to Watchtower requirements
	 *
	 * @author mcool
	 */
	static class WatchtowerPMDConfiguration extends PMDConfiguration {

		/**
		 * set usual defaults
		 */
		private WatchtowerPMDConfiguration() {
			setMinimumPriority(RulePriority.LOW);
			setReportProperties(new Properties());
			setShowSuppressedViolations(false);
			setSourceEncoding(StandardCharsets.UTF_8);
			setSuppressMarker(PMDConfiguration.DEFAULT_SUPPRESS_MARKER);
			setFailOnViolation(true);
			setAnalysisCacheLocation(null);
			setIgnoreIncrementalAnalysis(true);
		}

		/**
		 * create a WatchtowerPMDConfiguration using all defaults and adding the supplied data
		 * overrides
		 *
		 * @param inputPath the starting directory/file to scan
		 * @param threads   the number of threads to use 0 is single threaded, 1 is multi threaded
		 *                  with 1 worker, etc
		 */
		WatchtowerPMDConfiguration(String inputPath, int threads) {
			this();
			addInputPath(Paths.get(inputPath));
			setThreads(threads);
		}
	}

	@Override
	public List<String> getDefaultFileTypes() {
		// PMD picks files by language, so the types are the extensions of the languages Watchtower enables.
		return Arrays.stream(com.tracelink.appsec.module.pmd.service.PMDLanguageSupport.values())
				.flatMap(language -> language.getPMDLanguage().getExtensions().stream())
				.map(extension -> "." + extension.toLowerCase(java.util.Locale.ROOT)).distinct().toList();
	}

	@Override
	public List<Class<? extends RuleDto>> getSupportedRuleClass() {
		return Arrays.asList(PMDCustomRuleDto.class, PMDProvidedRuleDto.class);
	}
}
