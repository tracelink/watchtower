package com.tracelink.appsec.module.pmd.scanner;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDRuleDto;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.ScanConfig;

import net.sourceforge.pmd.PMD;
import net.sourceforge.pmd.PMDConfiguration;
import net.sourceforge.pmd.Rule;
import net.sourceforge.pmd.RulePriority;
import net.sourceforge.pmd.RuleSet;
import net.sourceforge.pmd.RuleSetWriter;
import net.sourceforge.pmd.benchmark.TimeTracker;
import net.sourceforge.pmd.benchmark.TimingReport;
import net.sourceforge.pmd.lang.Language;
import net.sourceforge.pmd.lang.LanguageRegistry;
import net.sourceforge.pmd.lang.LanguageVersion;
import net.sourceforge.pmd.renderers.Renderer;

/**
 * {@link IScanner} for PMD. Manages the PMD lifecycle and reporting
 *
 * @author csmith, mcool
 */
public class PMDScanner implements IScanner {
	public static final Logger LOG = LoggerFactory.getLogger(PMDScanner.class);
	public static final String DEFAULT_PMD_RULES =
			"rules/security/sec-deserialization.xml,rules/security/sec-xxe.xml";
	private PMDRuleService ruleService;

	public PMDScanner(PMDRuleService ruleService) {
		this.ruleService = ruleService;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PMDReport scan(ScanConfig config) {
		// Write PMD rules to an XML file
		Path rulesetPath = null;
		try {
			rulesetPath = writeRulesetToFile(config.getRuleset());
		} catch (Exception e) {
			LOG.error("Exception writing ruleset to resources", e);
			if (rulesetPath != null) {
				FileUtils.deleteQuietly(rulesetPath.toFile());
			}
			return null;
		}
		// Create configuration
		WatchtowerPMDConfiguration pmdConfig =
				new WatchtowerPMDConfiguration(config.getWorkingDirectory().toString(),
						rulesetPath.toString(), config.getThreads());
		PMDRenderer renderer = new PMDRenderer();
		pmdConfig.setRenderer(renderer);
		// Perform scan
		TimingReport timing;
		if (config.isBenchmarkEnabled()) {
			TimeTracker.startGlobalTracking();
		}

		PMD.runPmd(pmdConfig);

		if (config.isBenchmarkEnabled()) {
			timing = TimeTracker.stopGlobalTracking();
			renderer.addTimingReport(timing);
		}
		// Delete ruleset XML file
		FileUtils.deleteQuietly(rulesetPath.toFile());
		return renderer.createReport();
	}

	private Path writeRulesetToFile(RulesetDto dto)
			throws IOException, RulesetException {
		String uri = "pmd-" + dto.getId() + "-";
		Path rulesetPath = Files.createTempFile(uri, ".xml").toFile().getCanonicalFile()
				.getAbsoluteFile().toPath();

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

		RuleSet ruleset = RuleSet.create(dto.getName(), dto.getDescription(),
				rulesetPath.getFileName().toString(),
				new ArrayList<>(), new ArrayList<>(), rules);

		try (OutputStream os = new FileOutputStream(rulesetPath.toFile())) {
			RuleSetWriter writer = new RuleSetWriter(os);
			writer.write(ruleset);
		}

		return rulesetPath;
	}

	/**
	 * Mapping object from {@code PMDConfiguration} to Watchtower requirements
	 *
	 * @author mcool
	 */
	static class WatchtowerPMDConfiguration extends PMDConfiguration {
		private Renderer renderer;

		/**
		 * set usual defaults
		 */
		private WatchtowerPMDConfiguration() {
			setInputFilePath(null);
			setInputUri(null);
			setBenchmark(false);
			setDebug(false);
			setMinimumPriority(RulePriority.LOW);
			setReportProperties(new Properties());
			setReportShortNames(false);
			setRuleSetFactoryCompatibilityEnabled(true);
			setShowSuppressedViolations(false);
			setSourceEncoding("UTF-8");
			setStressTest(false);
			setSuppressMarker(PMD.SUPPRESS_MARKER);
			setFailOnViolation(true);
			setAnalysisCacheLocation(null);
			setIgnoreIncrementalAnalysis(true);

			Language language = LanguageRegistry.getDefaultLanguage();
			LanguageVersion languageVersion =
					getLanguageVersionDiscoverer().getDefaultLanguageVersion(language);
			if (languageVersion != null) {
				getLanguageVersionDiscoverer().setDefaultLanguageVersion(languageVersion);
			}
			try {
				prependClasspath(null);
			} catch (IOException e) {
				throw new IllegalArgumentException("Invalid auxiliary classpath", e);
			}
		}

		/**
		 * create a WatchtowerPMDConfiguration using all defaults and adding the supplied data
		 * overrides
		 *
		 * @param inputPath the starting directory/file to scan
		 * @param ruleSets  the rulesets to use (in resources directory)
		 * @param threads   the number of threads to use 0 is single threaded, 1 is multi threaded
		 *                  with 1 worker, etc
		 */
		WatchtowerPMDConfiguration(String inputPath, String ruleSets, int threads) {
			this();
			setInputPaths(inputPath);
			setRuleSets(ruleSets);
			setThreads(threads);
			setReportFile("");
		}

		void setRenderer(Renderer renderer) {
			this.renderer = renderer;
		}

		public Renderer getRenderer() {
			return renderer;
		}

		/**
		 * lazy instantiate the renderer, and continue to use the same renderer (don't recreate on
		 * each call)
		 */
		@Override
		public Renderer createRenderer() {
			if (renderer == null) {
				Renderer superRenderer = super.createRenderer();
				setRenderer(superRenderer);
			}
			return renderer;
		}
	}

	@Override
	public Class<? extends RuleDto> getSupportedRuleClass() {
		return PMDCustomRuleDto.class;
	}
}
