package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ProviderFindingTitlesTest {

	@ParameterizedTest
	@CsvSource(delimiter = '|', nullValues = "null", value = {
			"Sensitive AWS finding: PRIVILEGE_ESCALATION | PRIVILEGE_ESCALATION | Privilege escalation",
			"AWS security finding: SQL_INJECTION | SQL_INJECTION | SQL injection",
			"[Requirement: ASA Base Pack/tenant-isolation] Missing tenant check | null | Tenant isolation",
			"[Requirement: ] Missing tenant check | null | Missing tenant check",
			"Failed scans look clean | COMMAND_INJECTION | Failed scans look clean",
			"null | CROSS_SITE_SCRIPTING | Cross site scripting",
			"null | null | AWS security finding",
			"AWS security finding | null | AWS security finding",
			"UNKNOWN | null | AWS security finding"})
	void titlesReadInPlainWords(String name, String riskType, String expected) {
		assertEquals(expected, ProviderFindingTitles.plain(name, riskType));
	}
}
