package com.tracelink.appsec.module.betterleaks.verify;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksRuleIds;

/**
 * Which Betterleaks rules may be verified live: the ids in {@link #RULES_PROPERTY}, each of which
 * must be a built-in rule with a provider check (a {@code validate} block) in the pinned binary.
 * A verification sends the secret to that provider, so security decides the list; {@code *}
 * allows every rule that has a check. A misconfigured id fails startup rather than silently
 * never offering "Verify live".
 *
 * @author Watchtower
 */
@Component
@ConditionalOnProperty(name = BetterleaksVerificationService.ENABLED_PROPERTY,
		havingValue = "true")
public class VerifiableRules {

	public static final String RULES_PROPERTY = "watchtower.betterleaks.verification.rules";

	/** Major cloud and SCM providers, whose checks call only the provider's own API. */
	public static final String DEFAULT_RULES = "aws-access-token,azure-ad-client-secret,"
			+ "gcp-api-key,github-app-token,github-fine-grained-pat,github-oauth,github-pat,"
			+ "gitlab-pat";

	static final String ALL = "*";

	private static final String RESOURCE = "/rules/betterleaks-validating-rules.json";

	private final Set<String> ruleIds;

	@Autowired
	public VerifiableRules(
			@Value("${" + RULES_PROPERTY + ":" + DEFAULT_RULES + "}") String configured) {
		this(configured, validatingRules());
	}

	VerifiableRules(String configured, Set<String> validating) {
		String trimmed = StringUtils.trimToEmpty(configured);
		if (ALL.equals(trimmed)) {
			this.ruleIds = Set.copyOf(validating);
			return;
		}
		Set<String> ids = new TreeSet<>();
		for (String id : trimmed.split(",")) {
			String ruleId = id.trim();
			if (ruleId.isEmpty()) {
				continue;
			}
			if (BetterleaksRuleIds.isCustom(ruleId) || !validating.contains(ruleId)) {
				throw new IllegalStateException(RULES_PROPERTY + " lists '" + ruleId
						+ "', which is not a built-in Betterleaks rule with a provider check");
			}
			ids.add(ruleId);
		}
		this.ruleIds = Set.copyOf(ids);
	}

	/**
	 * @param ruleId a Betterleaks rule id
	 * @return true if findings of that rule may be verified live
	 */
	public boolean isVerifiable(String ruleId) {
		return ruleId != null && ruleIds.contains(ruleId);
	}

	/**
	 * @return the verifiable rule ids
	 */
	public Set<String> ruleIds() {
		return ruleIds;
	}

	/** Shape of the pinned resource. */
	record ValidatingRuleFile(String betterleaksVersion, String source, List<String> ruleIds) {
	}

	/**
	 * @return ids of the built-in rules with a provider check in the pinned binary
	 */
	static Set<String> validatingRules() {
		return Set.copyOf(readResource().ruleIds());
	}

	/**
	 * @return the binary version the pinned list was taken from
	 */
	static String validatingRulesVersion() {
		return readResource().betterleaksVersion();
	}

	private static ValidatingRuleFile readResource() {
		try (InputStream in = VerifiableRules.class.getResourceAsStream(RESOURCE)) {
			if (in == null) {
				throw new IllegalStateException("Missing " + RESOURCE);
			}
			ValidatingRuleFile file = new ObjectMapper().readValue(in, ValidatingRuleFile.class);
			if (file.ruleIds() == null
					|| !file.ruleIds().stream().allMatch(BetterleaksRuleIds::isValid)) {
				throw new IllegalStateException("Invalid rule ids in " + RESOURCE);
			}
			return file;
		} catch (IOException e) {
			throw new IllegalStateException("Unreadable " + RESOURCE, e);
		}
	}
}
