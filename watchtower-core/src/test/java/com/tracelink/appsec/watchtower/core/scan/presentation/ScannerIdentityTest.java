package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class ScannerIdentityTest {

	@Test
	void ruleNamesLoseOnlyAKnownScannerPrefix() {
		assertEquals("private-key", ScannerIdentity.withoutScannerPrefix("Betterleaks: private-key"));
		assertEquals("Note: keep this", ScannerIdentity.withoutScannerPrefix("Note: keep this"));
		assertEquals("InsecureRandom", ScannerIdentity.withoutScannerPrefix("InsecureRandom"));
		assertEquals("", ScannerIdentity.withoutScannerPrefix(null));
	}

	@Test
	void moduleNamesResolveToOneIdentity() {
		assertEquals("AWS Security Agent", ScannerIdentity.of("AwsSecurityAgent").name());
		assertEquals("coffee", ScannerIdentity.of("PMD").icon());
	}

	@Test
	void moduleRulesetNamesReadAsPeopleSayThem() {
		assertEquals("AWS Security Agent · Security review",
				ScannerIdentity.readableRulesetName("AwsSecurityAgent - Security review"));
		assertEquals("Default Dev Ruleset", ScannerIdentity.readableRulesetName("Default Dev Ruleset"));
		assertEquals("Team - Java", ScannerIdentity.readableRulesetName("Team - Java"));
		assertEquals("", ScannerIdentity.readableRulesetName(null));
		assertEquals("cloud", ScannerIdentity.rulesetScanner("AwsSecurityAgent - Security review").icon());
		org.junit.jupiter.api.Assertions.assertNull(ScannerIdentity.rulesetScanner("Team - Java"));
		org.junit.jupiter.api.Assertions.assertNull(ScannerIdentity.rulesetScanner(null));
	}
}
