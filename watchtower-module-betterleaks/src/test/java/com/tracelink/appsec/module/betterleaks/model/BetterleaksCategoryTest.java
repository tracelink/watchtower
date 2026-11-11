package com.tracelink.appsec.module.betterleaks.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class BetterleaksCategoryTest {

	@ParameterizedTest
	@CsvSource({
			"private-key, PRIVATE_KEY",
			"polymarket-private-key, PRIVATE_KEY",
			"aws-access-token, CLOUD",
			"gcp-api-key, CLOUD",
			"azure-ad-client-secret, CLOUD",
			"digitalocean-pat, CLOUD",
			"github-pat, SCM",
			"gitlab-pat, SCM",
			"bitbucket-client-secret, SCM",
			"generic-api-key, GENERIC",
			"jwt, GENERIC",
			"jwt-base64, GENERIC",
			"curl-auth-header, GENERIC",
			"slack-bot-token, SAAS",
			"mailgun-private-api-token, SAAS",
			"privateai-api-token, SAAS",
			"awesome-new-vendor-token, SAAS",
			"custom-example-internal-token, CUSTOM"
	})
	public void testClassifiesARuleIdByItsFamily(String ruleId, BetterleaksCategory expected) {
		Assertions.assertEquals(expected, BetterleaksCategory.of(ruleId));
	}

	@Test
	public void testDefaultPrioritiesFollowTheDesign() {
		Assertions.assertEquals(RulePriority.HIGH, BetterleaksCategory.PRIVATE_KEY.getDefaultPriority());
		Assertions.assertEquals(RulePriority.HIGH, BetterleaksCategory.CLOUD.getDefaultPriority());
		Assertions.assertEquals(RulePriority.HIGH, BetterleaksCategory.SCM.getDefaultPriority());
		Assertions.assertEquals(RulePriority.MEDIUM_HIGH,
				BetterleaksCategory.SAAS.getDefaultPriority());
		Assertions.assertEquals(RulePriority.MEDIUM,
				BetterleaksCategory.GENERIC.getDefaultPriority());
	}

	@Test
	public void testNullOrBlankIdIsGeneric() {
		Assertions.assertEquals(BetterleaksCategory.GENERIC, BetterleaksCategory.of(null));
		Assertions.assertEquals(BetterleaksCategory.GENERIC, BetterleaksCategory.of(" "));
	}
}
