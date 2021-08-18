package com.tracelink.appsec.module.eslint.interpreter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.samskivert.mustache.Mustache;
import com.samskivert.mustache.MustacheException;
import com.samskivert.mustache.Template;
import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.engine.ProcessResult;
import com.tracelink.appsec.module.eslint.engine.json.EsLintRuleJsonModel;
import com.tracelink.appsec.module.eslint.engine.json.EsLintRulesetJsonModel;
import com.tracelink.appsec.module.eslint.engine.json.LinterMessage;
import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDto;
import com.tracelink.appsec.watchtower.core.module.interpreter.IRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.module.interpreter.RulesetInterpreterException;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Implementation of an {@link IRulesetInterpreter} for importing and exporting rulesets containing
 * ESLint rules.
 *
 * @author mcool
 */
public class EsLintRulesetInterpreter implements IRulesetInterpreter {

	private static final Logger LOG = LoggerFactory.getLogger(EsLintRulesetInterpreter.class);
	private static final Gson GSON = new Gson();
	private static final String CANNOT_BE_PARSED = "The ESLint ruleset cannot be parsed. ";
	private static final String INCORRECTLY_FORMATTED =
			"The ESLint ruleset is incorrectly formatted. ";
	private static final String PLEASE_CHECK_LOG = "Please check the log for more details.";

	private Template rulesetTemplate;
	private final LinterEngine engine;

	public EsLintRulesetInterpreter(LinterEngine engine) {
		this.engine = engine;
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("templates/export/ruleset.js")) {
			String exampleRuleset = IOUtils.toString(is, Charset.defaultCharset());
			rulesetTemplate = Mustache.compiler().compile(exampleRuleset);
		} catch (IOException | NullPointerException e) {
			LOG.error("Cannot load ESLint ruleset export template");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RulesetDto importRuleset(InputStream inputStream)
			throws IOException, RulesetInterpreterException {
		// Get content of the ruleset as a string
		String lines;
		try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
			lines = br.lines().collect(Collectors.joining("\n"));
		}
		// Parse the ruleset
		EsLintRulesetJsonModel rulesetModel = parseRuleset(lines);
		// Create ruleset DTO
		RulesetDto rulesetDto = new RulesetDto();
		rulesetDto.setName(rulesetModel.getName());
		rulesetDto.setDescription(rulesetModel.getDescription());
		// Create rule DTOs
		Set<RuleDto> rules = new TreeSet<>();
		addCustomRules(rules, rulesetModel.getCustomRules(), rulesetModel.getPriorities());
		addCoreRules(rules, rulesetModel.getPriorities());
		rulesetDto.setRules(rules);
		return rulesetDto;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public InputStream exportRuleset(RulesetDto rulesetDto)
			throws IOException, RulesetInterpreterException {
		// Filter ruleset for ESLint rules
		List<EsLintRuleDto> esLintRules = rulesetDto.getAllRules().stream()
				.filter(r -> r instanceof EsLintRuleDto).map(r -> (EsLintRuleDto) r)
				.collect(Collectors.toList());
		// If there are no ESLint rules, return null
		if (esLintRules.isEmpty()) {
			return null;
		}
		// Create parameters map for ruleset template
		Map<String, Object> params = new HashMap<>();
		params.put("name", rulesetDto.getName());
		params.put("description", rulesetDto.getDescription());
		params.put("customRules",
				esLintRules.stream().filter(r -> !r.isCore()).collect(Collectors.toList()));
		params.put("priorities", esLintRules.stream()
				.collect(Collectors.toMap(RuleDto::getName, RuleDto::getPriority)).entrySet());
		// Execute template and return
		try {
			return new ByteArrayInputStream(rulesetTemplate.execute(params).getBytes());
		} catch (MustacheException e) {
			LOG.error("Cannot export ruleset", e);
			throw new RulesetInterpreterException(
					"Error converting ruleset to template. " + PLEASE_CHECK_LOG);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getExtension() {
		return "js";
	}

	/**
	 * Parses the given JS ruleset string into an {@link EsLintRulesetJsonModel}, which is a JSON
	 * representation.
	 *
	 * @param ruleset the ruleset string to parse
	 * @return a JSON representation of the ruleset
	 * @throws RulesetInterpreterException if the ruleset is invalid or cannot be parsed
	 */
	private EsLintRulesetJsonModel parseRuleset(String ruleset) throws RulesetInterpreterException {
		// Parse the ruleset
		ProcessResult parseResult = engine.parseRuleset(ruleset);
		// Check if an error occurred while parsing
		if (parseResult.hasErrors()) {
			throw new RulesetInterpreterException(
					CANNOT_BE_PARSED + ": " + parseResult.getErrors());
		}

		if (parseResult.hasResults()) {
			String results = parseResult.getResults();
			// Check if results contain error messages
			if (results.startsWith("[") && results.endsWith("]")) {
				List<LinterMessage> messages = GSON
						.fromJson(results, LinterEngine.MESSAGES_TYPE_TOKEN.getType());
				throw new RulesetInterpreterException(
						CANNOT_BE_PARSED + messages.get(0).getMessage());
			}
		} else {
			throw new RulesetInterpreterException(CANNOT_BE_PARSED);
		}

		// Create ruleset JSON model
		EsLintRulesetJsonModel rulesetModel;
		try {
			rulesetModel = GSON.fromJson(parseResult.getResults(), EsLintRulesetJsonModel.class);
		} catch (JsonSyntaxException e) {
			LOG.error("Cannot translate ESLint ruleset to DTO", e);
			throw new RulesetInterpreterException(INCORRECTLY_FORMATTED + PLEASE_CHECK_LOG);
		}
		return rulesetModel;
	}

	/**
	 * Translates custom rule JSON models to DTOs and adds them to the given set of DTOs. Assigns
	 * each rule its priority using the given priority map.
	 *
	 * @param rules       rule DTO set to add custom rules to
	 * @param customRules custom rule JSON models to create DTOs from
	 * @param priorities  priorities map to assign each rule a priority
	 */
	private void addCustomRules(Set<RuleDto> rules, Map<String, EsLintRuleJsonModel> customRules,
			Map<String, Integer> priorities) throws RulesetInterpreterException {
		for (Map.Entry<String, EsLintRuleJsonModel> ruleEntry : customRules.entrySet()) {
			String name = ruleEntry.getKey();
			RuleDto rule = ruleEntry.getValue().toDto();
			rule.setName(name);
			// Set the priority for this rule
			if (priorities.containsKey(name)) {
				RulePriority priority = RulePriority.valueOf(priorities.get(name));
				rule.setPriority(priority);
			} else {
				throw new RulesetInterpreterException(
						"No rule priority provided for the custom rule \"" + name + "\".");
			}
			rules.add(rule);
		}
	}

	/**
	 * Creates core rule DTOs from the given priority map and adds them to the given set of DTOs.
	 * Ensures that if the rule does not have a custom implementation, it is actually a valid core
	 * rule.
	 *
	 * @param rules      rule DTO set to add custom rules to
	 * @param priorities priorities map to create core rule DTOs from
	 */
	private void addCoreRules(Set<RuleDto> rules, Map<String, Integer> priorities)
			throws RulesetInterpreterException {
		Set<String> customRules = rules.stream().map(RuleDto::getName)
				.collect(Collectors.toSet());

		Map<String, Map<String, String>> coreRules = engine.getCoreRules();

		for (Map.Entry<String, Integer> priorityEntry : priorities.entrySet()) {
			String name = priorityEntry.getKey();
			// Rule priorities for custom rules have already been set
			if (customRules.contains(name)) {
				continue;
			}
			// If rule is not in the custom rules, make sure it is a valid core rule
			if (!coreRules.containsKey(name)) {
				throw new RulesetInterpreterException(
						"No rule definition provided for the custom rule \"" + name + "\".");
			}
			// Create core rule
			EsLintRuleDto rule = new EsLintRuleDto();
			rule.setCore(true);
			rule.setName(name);
			rule.setMessage(coreRules.get(name).get("description"));
			rule.setExternalUrl(coreRules.get(name).get("url"));
			RulePriority priority = RulePriority.valueOf(priorityEntry.getValue());
			rule.setPriority(priority);
			rules.add(rule);
		}
	}

	@Override
	public InputStream exportExampleRuleset() throws IOException, RulesetInterpreterException {
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("Example ESLint Ruleset");
		ruleset.setDescription("Example ESLint ruleset to show necessary model values");
		EsLintRuleDto coreRule = new EsLintRuleDto();
		coreRule.setCore(true);
		coreRule.setName("Core ESLint Rule Name");
		coreRule.setPriority(RulePriority.MEDIUM_HIGH);
		EsLintRuleDto customRule = new EsLintRuleDto();
		customRule.setCore(false);
		customRule.setName("Custom ESLint Rule Name");
		customRule.setPriority(RulePriority.MEDIUM_LOW);
		customRule.setMessage("Example Description");
		customRule.setExternalUrl("https://example.com/more-info");
		customRule.setCreateFunction("create(context) {\n"
				+ "    // Add JS code here\n"
				+ "    return {\n"
				+ "        ExpressionStatement(node) {\n"
				+ "            context.report({ node, messageId: \"custom\" });\n"
				+ "        }\n"
				+ "    };\n"
				+ "}");
		EsLintMessageDto customMessage = new EsLintMessageDto("custom", "Message to User");
		customRule.setMessages(Collections.singletonList(customMessage));
		ruleset.setRules(new HashSet<>(Arrays.asList(coreRule, customRule)));
		return exportRuleset(ruleset);
	}
}
