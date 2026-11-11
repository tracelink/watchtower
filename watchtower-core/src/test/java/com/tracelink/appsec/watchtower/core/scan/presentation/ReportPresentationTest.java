package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation;

/** PR report redesign (UAT walkthrough, 2026-10-15): readable messages, severity bar, bypass groups. */
class ReportPresentationTest {

	@Test
	void unexpandedMessagePlaceholdersBecomeReadableSentences() {
		assertEquals("This parameter is not assigned and could be declared final",
				FindingPresentationModel.readableGuidance("MethodArgumentCouldBeFinal",
						"Parameter ''{0}'' is not assigned and could be declared final"));
		assertEquals("Avoid unused private fields such as it.",
				FindingPresentationModel.readableGuidance("Other", "Avoid unused private fields such as ''{0}''."));
		assertEquals("Comment is required", FindingPresentationModel.readableGuidance("CommentRequired", "Comment is required"));
		assertEquals("Review whether this field can be declared final. The historical message did not identify the field.",
				FindingPresentationModel.readableGuidance("ImmutableField", "Field ''{0}'' may be declared final"));
	}

	@Test
	void severityBreakdownOrdersHighestFirstWithShares() {
		List<FindingPresentationModel> findings = FindingPresentationModel.fromPullRequest(List.of(
				violation("A", "Medium", 3, "src/A.java", 1), violation("B", "High", 1, "src/A.java", 2),
				violation("C", "Medium", 3, "src/B.java", 3), violation("D", "Medium", 3, "src/B.java", 4)));

		List<SeverityBreakdown> breakdown = SeverityBreakdown.of(findings);

		assertEquals(List.of("1", "3"), breakdown.stream().map(SeverityBreakdown::key).toList());
		assertEquals(3, breakdown.get(1).count());
		assertEquals("75.0%", breakdown.get(1).getWidth());
		assertEquals("A.java:1", findings.get(0).getShortLocation());
	}

	@Test
	void reviewMarkersAndPerFileSeveritiesComeFromTheFindings() {
		List<FindingPresentationModel> findings = FindingPresentationModel.fromPullRequest(List.of(
				violation("A", "High", 1, "src/A.java", 1), violation("B", "Medium", 3, "src/A.java", 2),
				violation("C", "Medium", 3, "src/B.java", 3)));
		findings.get(0).withReview("FALSE_POSITIVE");

		assertEquals("false", findings.get(0).getReviewState());
		assertEquals("cancel", findings.get(0).getReviewIcon());
		assertEquals("Not reviewed", findings.get(1).getReviewLabel());
		assertEquals(List.of("1", "3"), SeverityBreakdown.forFile(findings, "src/A.java").stream().map(SeverityBreakdown::key).toList());
		assertEquals(List.of(), SeverityBreakdown.forFile(null, "src/A.java"));
	}

	@Test
	void bypassCoverageGroupsRulesByFileOnce() {
		BypassCoverage coverage = BypassCoverage.of(List.of(
				violation("CommentRequired", "Medium", 3, "src/main/A.java", 12),
				violation("CommentRequired", "Medium", 3, "src/main/A.java", 13),
				violation("Secret", "High", 1, "src/main/A.java", 14),
				violation("Secret", "High", 1, "notes.txt", 1)));

		assertEquals(3, coverage.total());
		assertEquals(List.of("notes.txt", "A.java"), coverage.files().stream().map(BypassCoverage.FileGroup::name).toList());
		assertEquals("src/main/A.java", coverage.files().get(1).path());
		assertEquals(List.of("Secret", "CommentRequired"),
				coverage.files().get(1).rules().stream().map(BypassCoverage.Rule::name).toList());
		assertEquals(List.of(1, 3), coverage.severities().stream().map(BypassCoverage.SeverityCount::severityValue).toList());
	}

	private static PRScanResultViolation violation(String rule, String severity, int value, String file, int line) {
		PRScanResultViolation violation = new PRScanResultViolation();
		violation.setViolationName(rule);
		violation.setSeverity(severity);
		violation.setSeverityValue(value);
		violation.setFileName(file);
		violation.setLineNumber(line);
		violation.setMessage("message");
		return violation;
	}
}
