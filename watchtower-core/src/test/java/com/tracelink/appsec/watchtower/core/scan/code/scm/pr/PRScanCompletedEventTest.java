package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;

public class PRScanCompletedEventTest {

	private static final PRScanCompletedEvent.Finding FINDING = new PRScanCompletedEvent.Finding(
			1L, "rule", RulePriority.HIGH, "App.java", 3, true, false);

	@Test
	public void testFindingsAreACopyTheCallerCannotChange() {
		List<PRScanCompletedEvent.Finding> findings = new ArrayList<>(List.of(FINDING));
		PRScanCompletedEvent event =
				new PRScanCompletedEvent(1L, BDDMockito.mock(PullRequest.class), findings);

		findings.clear();

		Assertions.assertEquals(List.of(FINDING), event.findings());
		Assertions.assertThrows(UnsupportedOperationException.class,
				() -> event.findings().add(FINDING));
	}

	@Test
	public void testFindingSnapshotsAViolation() {
		PullRequestViolationEntity violation = BDDMockito.mock(PullRequestViolationEntity.class);
		BDDMockito.when(violation.getId()).thenReturn(9L);
		BDDMockito.when(violation.getViolationName()).thenReturn("rule");
		BDDMockito.when(violation.getSeverity()).thenReturn(RulePriority.MEDIUM);
		BDDMockito.when(violation.getFileName()).thenReturn("a/B.java");
		BDDMockito.when(violation.getLineNum()).thenReturn(4);
		BDDMockito.when(violation.isNewViolation()).thenReturn(true);
		BDDMockito.when(violation.isBlocking()).thenReturn(true);

		Assertions.assertEquals(new PRScanCompletedEvent.Finding(9L, "rule",
				RulePriority.MEDIUM, "a/B.java", 4, true, true),
				PRScanCompletedEvent.Finding.of(violation));
	}
}
