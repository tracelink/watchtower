package com.tracelink.appsec.watchtower.core.scan.code.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

/** The rules a scanner could not run although it ran: kept by name, never blank, and carried through a join. */
class CodeScanReportFailedRulesTest {
	@Test
	void aReportStartsWithNoFailedRules() {
		assertTrue(new CodeScanReport().getFailedRules().isEmpty());
	}

	@Test
	void aFailedRuleIsKeptByNameWithTheFirstReasonAndBlankNamesAreIgnored() {
		var report = new CodeScanReport();

		report.addFailedRule("LoosePackageCoupling", "No packages or classes specified");
		report.addFailedRule("LoosePackageCoupling", "a later, different reason");
		report.addFailedRule("", "no name");
		report.addFailedRule(null, "no name");

		assertEquals(Map.of("LoosePackageCoupling", "No packages or classes specified"), report.getFailedRules());
	}

	@Test
	void theListCannotBeChangedFromOutside() {
		var report = new CodeScanReport();
		report.addFailedRule("A", "why");

		assertThrows(UnsupportedOperationException.class, () -> report.getFailedRules().put("B", "x"));
	}

	@Test
	void joiningReportsKeepsTheFailedRulesOfBoth() {
		var first = new CodeScanReport();
		first.addFailedRule("A", "first");
		var second = new CodeScanReport();
		second.addFailedRule("B", "second");
		second.addFailedRule("A", "ignored: A is already there");

		first.join(second);

		assertEquals(Map.of("A", "first", "B", "second"), first.getFailedRules());
	}
}
