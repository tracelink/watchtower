package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class SeverityCountsTest {

	@Test
	public void countsFormatAndParseRoundTrip() {
		SeverityCounts counts = SeverityCounts.of(List.of(RulePriority.HIGH, RulePriority.HIGH,
				RulePriority.MEDIUM, RulePriority.INFORMATIONAL));

		Assertions.assertEquals("2,0,1,0,0,1", counts.format());
		Assertions.assertEquals(4, counts.total());
		Assertions.assertEquals(3, counts.totalExcludingInformational());
		Assertions.assertEquals(RulePriority.HIGH, counts.highest());
		Assertions.assertEquals(counts.format(), SeverityCounts.parse(counts.format()).format());
	}

	@Test
	public void parseToleratesMissingAndMalformedValues() {
		SeverityCounts counts = SeverityCounts.parse("1,x,-3");

		Assertions.assertEquals(1, counts.get(RulePriority.HIGH));
		Assertions.assertEquals(0, counts.get(RulePriority.MEDIUM_HIGH));
		Assertions.assertEquals(0, counts.get(RulePriority.MEDIUM));
		Assertions.assertEquals(1, counts.total());
		Assertions.assertNull(SeverityCounts.parse(null).highest());
	}

	@Test
	public void entityKeepsTotalHighestAndCountsInStep() {
		RepoScanEntity scan = new RepoScanEntity();
		scan.setSeverityCounts(SeverityCounts.of(List.of(RulePriority.LOW, RulePriority.MEDIUM)));

		Assertions.assertEquals(2, scan.getFindingCount());
		Assertions.assertEquals(RulePriority.MEDIUM, scan.getMaxSeverity());
		Assertions.assertEquals("0,0,1,0,1,0", scan.getSeverityCounts().format());

		scan.setSeverityCounts(SeverityCounts.empty());
		Assertions.assertNull(scan.getMaxSeverity());
	}
}
