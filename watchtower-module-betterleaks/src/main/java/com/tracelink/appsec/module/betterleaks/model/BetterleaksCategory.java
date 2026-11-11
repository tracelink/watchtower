package com.tracelink.appsec.module.betterleaks.model;

import java.util.Locale;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Family of secret a Betterleaks rule detects, which decides the priority a provided rule starts
 * with. Only the starting point: ruleset owners change priorities in the rule editor, and those
 * edits survive restarts.
 *
 * @author Watchtower
 */
public enum BetterleaksCategory {
	/** Private keys - full identity compromise. */
	PRIVATE_KEY(RulePriority.HIGH, "Private key"),
	/** Cloud provider credentials - infrastructure compromise. */
	CLOUD(RulePriority.HIGH, "Cloud"),
	/** Source control tokens - code and pipeline compromise. */
	SCM(RulePriority.HIGH, "Source control"),
	/** Third-party SaaS API keys. */
	SAAS(RulePriority.MEDIUM_HIGH, "SaaS"),
	/** Generic, entropy-based or structural matches - the noisiest rules. */
	GENERIC(RulePriority.MEDIUM, "Generic"),
	/** Written in the Watchtower designer; the author chooses the priority. */
	CUSTOM(RulePriority.MEDIUM, "Custom");

	private static final String CUSTOM_PREFIX = "custom-";

	private static final Set<String> CLOUD_PREFIXES = Set.of("aws", "gcp", "azure", "alibaba",
			"digitalocean", "cloudflare", "hashicorp", "heroku", "ibm", "linode", "oci",
			"scaleway", "tencent", "yandex", "civo", "vultr");

	private static final Set<String> SCM_PREFIXES =
			Set.of("github", "gitlab", "bitbucket", "gitea");

	private static final Set<String> GENERIC_PREFIXES = Set.of("generic", "jwt", "curl");

	private final RulePriority defaultPriority;

	private final String displayName;

	BetterleaksCategory(RulePriority defaultPriority, String displayName) {
		this.defaultPriority = defaultPriority;
		this.displayName = displayName;
	}

	/**
	 * @return the category in plain words for the rule editor, e.g. {@code Private key}
	 */
	public String getDisplayName() {
		return displayName;
	}

	public RulePriority getDefaultPriority() {
		return defaultPriority;
	}

	/**
	 * Classifies a Betterleaks rule id (e.g. {@code aws-access-token}) by its vendor prefix.
	 *
	 * @param ruleId the Betterleaks rule id
	 * @return the rule's category; {@link #GENERIC} when the id is blank
	 */
	public static BetterleaksCategory of(String ruleId) {
		if (StringUtils.isBlank(ruleId)) {
			return GENERIC;
		}
		String id = ruleId.trim().toLowerCase(Locale.ROOT);
		if (id.startsWith(CUSTOM_PREFIX)) {
			return CUSTOM;
		}
		if (id.equals("private-key") || id.endsWith("-private-key")) {
			return PRIVATE_KEY;
		}
		String prefix = id.split("-", 2)[0];
		if (CLOUD_PREFIXES.contains(prefix)) {
			return CLOUD;
		}
		if (SCM_PREFIXES.contains(prefix)) {
			return SCM;
		}
		if (GENERIC_PREFIXES.contains(prefix)) {
			return GENERIC;
		}
		return SAAS;
	}
}
