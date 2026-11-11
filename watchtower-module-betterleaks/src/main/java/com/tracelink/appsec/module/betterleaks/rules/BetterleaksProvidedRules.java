package com.tracelink.appsec.module.betterleaks.rules;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCategory;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * The provided rules, read from a copy of the pinned Betterleaks binary's built-in default config
 * ({@code betterleaks config show}), trimmed to the rules that report on their own. The engine
 * runs these by id against the binary's own definitions, so the copy only has to agree on ids -
 * an id the binary does not know fails the scan loudly (see {@code BetterleaksEngineBinaryTest}).
 * <p>
 * Regenerate the resource whenever {@link BetterleaksModule#BETTERLEAKS_VERSION} changes.
 *
 * @param version the Betterleaks version the rules were taken from
 * @param rules   the provided rules, each at its category's default priority
 * @author Watchtower
 */
public record BetterleaksProvidedRules(String version, List<BetterleaksProvidedRuleDto> rules) {

	public static final String DEFAULT_RULESET_NAME = "Betterleaks - Default";

	public static final String EXTERNAL_URL = "https://github.com/betterleaks/betterleaks";

	static final String RESOURCE = "/rules/betterleaks-default-rules.json";

	static final String RULE_NAME_PREFIX = "Betterleaks: ";

	private static final String DEFAULT_RULESET_DESCRIPTION =
			"Secrets detection with the Betterleaks " + BetterleaksModule.BETTERLEAKS_VERSION
					+ " default rules";

	private static final ObjectMapper MAPPER = new ObjectMapper();

	public BetterleaksProvidedRules {
		rules = List.copyOf(rules);
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	record RuleDefinition(String id, String description, String confidence) {
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	record RuleFile(String betterleaksVersion, List<RuleDefinition> rules) {
	}

	/**
	 * Reads the bundled rules. Every call builds new rule objects, since registration sets
	 * priorities and rulesets on them.
	 *
	 * @return the provided rules
	 * @throws IllegalStateException if the resource is missing, unreadable, or was generated from
	 *                               a different Betterleaks version than the module runs
	 */
	public static BetterleaksProvidedRules load() {
		RuleFile file = readRuleFile();
		if (!BetterleaksModule.BETTERLEAKS_VERSION.equals(file.betterleaksVersion())) {
			throw new IllegalStateException("Provided Betterleaks rules are for version "
					+ file.betterleaksVersion() + " but the module runs "
					+ BetterleaksModule.BETTERLEAKS_VERSION + "; regenerate " + RESOURCE);
		}
		return new BetterleaksProvidedRules(file.betterleaksVersion(),
				file.rules().stream().map(BetterleaksProvidedRules::toRule).toList());
	}

	private static RuleFile readRuleFile() {
		try (InputStream is = BetterleaksProvidedRules.class.getResourceAsStream(RESOURCE)) {
			if (is == null) {
				throw new IllegalStateException("Missing provided rules resource " + RESOURCE);
			}
			return MAPPER.readValue(is, RuleFile.class);
		} catch (IOException e) {
			throw new IllegalStateException("Unreadable provided rules resource " + RESOURCE, e);
		}
	}

	private static BetterleaksProvidedRuleDto toRule(RuleDefinition definition) {
		BetterleaksCategory category = BetterleaksCategory.of(definition.id());
		BetterleaksProvidedRuleDto rule = new BetterleaksProvidedRuleDto();
		rule.setBetterleaksId(definition.id());
		rule.setName(RULE_NAME_PREFIX + definition.id());
		rule.setMessage(definition.description());
		rule.setExternalUrl(EXTERNAL_URL);
		rule.setCategory(category);
		rule.setPriority(category.getDefaultPriority());
		rule.setConfidence(definition.confidence());
		return rule;
	}

	/**
	 * The provided ruleset holding every rule. It blocks at {@link RulePriority#MEDIUM} so the
	 * generic-secret rules, which start at MEDIUM, still block.
	 *
	 * @return the "Betterleaks - Default" provided ruleset
	 */
	public RulesetDto toDefaultRuleset() {
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName(DEFAULT_RULESET_NAME);
		ruleset.setDescription(DEFAULT_RULESET_DESCRIPTION);
		ruleset.setDesignation(RulesetDesignation.PROVIDED);
		ruleset.setBlockingLevel(RulePriority.MEDIUM);
		Set<RuleDto> ruleSet = new LinkedHashSet<>(rules);
		ruleset.setRules(ruleSet);
		return ruleset;
	}
}
