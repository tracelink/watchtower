package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;

class ScanFindingSummaryTest {
	@Test
	void allScannersContributeToTotalAndSeverityChips() {
		var local = SeverityCounts.of(List.of(RulePriority.HIGH, RulePriority.MEDIUM_HIGH));
		var summary = ScanFindingSummary.of(local, 2,
				List.of(provider("aws", 19, true, Map.of("HIGH", 2, "MEDIUM", 9, "LOW", 8))));
		assertEquals(21, summary.total());
		assertEquals(19, summary.providerCount());
		assertEquals(List.of("3H", "1MH", "9M", "8L"),
				summary.severities().stream().map(SeverityCountPresentationModel::getCompactText).toList());
		assertEquals(summary.total(), summary.severities().stream()
				.mapToLong(SeverityCountPresentationModel::getCount).sum());
	}

	@Test
	void incompleteAndUnclassifiedImportedFindingsStayVisible() {
		var summary = ScanFindingSummary.of(SeverityCounts.empty(), 0, List.of(
				provider("aws", 3, false, Map.of("HIGH", 1)),
				provider("other", 2, true, Map.of("LOW", 2))));
		assertEquals(5, summary.total());
		assertTrue(summary.providerIncomplete());
		assertEquals(List.of("1H", "2L", "2 U"),
				summary.severities().stream().map(SeverityCountPresentationModel::getCompactText).toList());
	}

	private static ProviderAssessmentReference provider(String name, int imported,
			boolean complete, Map<String, Integer> severities) {
		var status = new RemoteAssessmentService.Status(name, complete ? "COMPLETE" : "PARTIAL",
				null, null, null, null, null, imported, 0, true, complete, null, 1,
				severities);
		return new ProviderAssessmentReference(name, name, null, status,
				null, null, null, null, Map.of(), 0);
	}
}
