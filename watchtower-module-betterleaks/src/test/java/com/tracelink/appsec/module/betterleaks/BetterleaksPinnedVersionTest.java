package com.tracelink.appsec.module.betterleaks;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.betterleaks.rules.BetterleaksProvidedRules;

/**
 * The image installs one Betterleaks version and the module's rules and flags were verified
 * against one. They must be the same, or a scan runs rule ids the binary may not have.
 */
public class BetterleaksPinnedVersionTest {

	private static final Pattern DOCKERFILE_PIN =
			Pattern.compile("(?m)^ARG BETTERLEAKS_VERSION=(\\S+)$");

	@Test
	public void testDockerfileInstallsTheVersionTheModuleWasVerifiedAgainst() throws Exception {
		// Surefire runs with the module directory as the working directory.
		Path dockerfile = Path.of("..", "Dockerfile");
		Assertions.assertTrue(Files.exists(dockerfile), "Dockerfile not found at " + dockerfile);

		Matcher pin = DOCKERFILE_PIN.matcher(Files.readString(dockerfile));

		Assertions.assertTrue(pin.find(), "Dockerfile has no ARG BETTERLEAKS_VERSION pin");
		Assertions.assertEquals(BetterleaksModule.BETTERLEAKS_VERSION, pin.group(1));
	}

	@Test
	public void testProvidedRulesWereTakenFromTheSameVersion() {
		Assertions.assertEquals(BetterleaksModule.BETTERLEAKS_VERSION,
				BetterleaksProvidedRules.load().version());
	}
}
