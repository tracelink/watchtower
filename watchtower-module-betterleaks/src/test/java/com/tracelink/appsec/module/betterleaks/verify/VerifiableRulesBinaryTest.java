package com.tracelink.appsec.module.betterleaks.verify;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.betterleaks.engine.BetterleaksEngine;
import com.tracelink.appsec.watchtower.core.process.ProcessRequest;
import com.tracelink.appsec.watchtower.core.process.ProcessResult;
import com.tracelink.appsec.watchtower.core.process.ProcessRunner;

/**
 * Keeps the pinned list of rules with a provider check equal to what the installed binary
 * reports, so an upgrade cannot silently offer "Verify live" for a rule that no longer checks.
 */
@Tag("requires-binary")
public class VerifiableRulesBinaryTest {

	@Test
	public void testThePinnedVerifiableRuleListMatchesTheBinary() {
		String binary = BetterleaksEngine.resolveBinary(System.getenv());
		Assumptions.assumeTrue(new BetterleaksEngine(new ProcessRunner(), binary).isAvailable(),
				"betterleaks binary not installed");
		ProcessResult result = new ProcessRunner().run(new ProcessRequest(
				List.of(binary, "config", "show"), null, Duration.ofSeconds(30),
				16L * 1024 * 1024));
		Assertions.assertTrue(result.isSuccess());

		Set<String> validating = new TreeSet<>();
		String ruleId = null;
		for (String line : result.stdout().lines().toList()) {
			if (line.startsWith("[[rules]]")) {
				ruleId = null;
			} else if (line.startsWith("id = ")) {
				ruleId = line.substring("id = ".length()).replace("'", "").replace("\"", "");
			} else if (line.startsWith("validate") && ruleId != null) {
				validating.add(ruleId);
			}
		}

		// Regenerate rules/betterleaks-validating-rules.json when this fails after an upgrade.
		Assertions.assertEquals(validating, new TreeSet<>(VerifiableRules.validatingRules()));
	}
}
