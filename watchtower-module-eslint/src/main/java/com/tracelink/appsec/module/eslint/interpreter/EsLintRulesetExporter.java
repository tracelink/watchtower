package com.tracelink.appsec.module.eslint.interpreter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.samskivert.mustache.Mustache;
import com.samskivert.mustache.MustacheException;
import com.samskivert.mustache.Template;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDto;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Class that exports rulesets containing ESLint rules.
 *
 * @author mcool
 */
public class EsLintRulesetExporter {

	private static final Logger LOG = LoggerFactory.getLogger(EsLintRulesetExporter.class);
	private static final String PLEASE_CHECK_LOG = "Please check the log for more details.";

	private Template rulesetTemplate;

	public EsLintRulesetExporter() {
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("templates/export/ruleset.js")) {
			String exampleRuleset = IOUtils.toString(is, Charset.defaultCharset());
			rulesetTemplate = Mustache.compiler().compile(exampleRuleset);
		} catch (IOException | NullPointerException e) {
			LOG.error("Cannot load ESLint ruleset export template");
		}
	}

	/**
	 * Export the given {@link RulesetDto} to a stream representing the content of the ruleset. This
	 * will be written to a local file for scanning. Returns null if there are no rules in the
	 * ruleset that the exporter knows how to export.
	 *
	 * @param rulesetDto ruleset DTO object to export
	 * @return stream containing representation of the given ruleset, or null if there are no rules
	 * @throws IOException      if an error occurs while creating the stream
	 * @throws RulesetException if the ruleset cannot be converted to the export template
	 */
	public InputStream exportRuleset(RulesetDto rulesetDto)
			throws IOException, RulesetException {
		// Filter ruleset for ESLint rules
		List<RuleDto> esLintRules = rulesetDto.getAllRules().stream()
				.filter(r -> r instanceof EsLintRuleDto)
				.collect(Collectors.toList());
		// If there are no ESLint rules, return null
		if (esLintRules.isEmpty()) {
			return null;
		}
		// Create parameters map for ruleset template
		Map<String, Object> params = new HashMap<>();
		params.put("name", rulesetDto.getName());
		params.put("description", rulesetDto.getDescription());
		// Custom rules are non-provided rules custom-defined with Meta objects
		params.put("customRules",
				esLintRules.stream().filter(r -> (r instanceof EsLintCustomRuleDto))
						.collect(Collectors.toList()));
		// Priorities contains all rule definitions (Provided and Custom) and their priority
		params.put("priorities", esLintRules.stream()
				.collect(Collectors.toMap(RuleDto::getName, RuleDto::getPriority)).entrySet());
		// Execute template and return
		try {
			return new ByteArrayInputStream(rulesetTemplate.execute(params).getBytes());
		} catch (MustacheException e) {
			LOG.error("Cannot export ruleset", e);
			throw new RulesetException(
					"Error converting ruleset to template. " + PLEASE_CHECK_LOG);
		}
	}

}
