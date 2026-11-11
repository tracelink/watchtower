package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertItem;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanAlerts.ScmAction;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

public class PRScanAlertsTest {

	private AlertService alertService;

	private SimpleMeterRegistry meterRegistry;

	private PullRequest pr;

	@BeforeEach
	public void setup() {
		alertService = BDDMockito.mock(AlertService.class);
		meterRegistry = new SimpleMeterRegistry();
		pr = new PullRequest("bb-cloud");
		pr.setRepoName("payments");
		pr.setPrId("42");
		pr.setCommitHash("abc123");
	}

	private AlertEvent raised() {
		ArgumentCaptor<AlertEvent> captor = ArgumentCaptor.forClass(AlertEvent.class);
		BDDMockito.verify(alertService).raise(captor.capture());
		return captor.getValue();
	}

	@Test
	public void testIncompleteScanRaisesScannerFailureAndCountsEachScanner() {
		new PRScanAlerts(alertService, meterRegistry).scanIncomplete(pr, List.of("Betterleaks"));

		AlertEvent alert = raised();
		Assertions.assertEquals(AlertTypeRegistry.SCANNER_FAILURE, alert.type());
		Assertions.assertEquals("bb-cloud", alert.apiLabel());
		Assertions.assertEquals("payments", alert.repoName());
		MatcherAssert.assertThat(alert.title(), Matchers.containsString("#42"));
		MatcherAssert.assertThat(alert.items().get(0).text(),
				Matchers.containsString("Betterleaks"));
		Assertions.assertEquals(1.0, meterRegistry.get(PRScanAlerts.INCOMPLETE_METRIC)
				.tag("scanner", "Betterleaks").counter().count());
	}

	@Test
	public void testIncompleteScanDedupesPerCommitAndScanner() {
		PRScanAlerts alerts = new PRScanAlerts(alertService, meterRegistry);
		alerts.scanIncomplete(pr, List.of("Betterleaks"));
		pr.setCommitHash("def456");
		alerts.scanIncomplete(pr, List.of("Betterleaks"));

		ArgumentCaptor<AlertEvent> captor = ArgumentCaptor.forClass(AlertEvent.class);
		BDDMockito.verify(alertService, BDDMockito.times(2)).raise(captor.capture());
		// An SQS redelivery of the same commit must not alert twice; a new push may.
		Assertions.assertNotEquals(captor.getAllValues().get(0).items().get(0).dedupeKey(),
				captor.getAllValues().get(1).items().get(0).dedupeKey());
		Assertions.assertEquals(captor.getAllValues().get(0).threadKey(),
				captor.getAllValues().get(1).threadKey());
	}

	@Test
	public void testNothingIncompleteRaisesNothing() {
		new PRScanAlerts(alertService, meterRegistry).scanIncomplete(pr, List.of());

		BDDMockito.verifyNoInteractions(alertService);
	}

	@Test
	public void testFailedScmActionsRaiseOneAlertListingEach() {
		PRScanAlerts alerts = new PRScanAlerts(alertService, meterRegistry);
		alerts.recordScmAction(ScmAction.COMMENT, false);
		alerts.recordScmAction(ScmAction.REQUEST_CHANGES, false);
		alerts.recordScmAction(ScmAction.DECLINE, true);
		alerts.raiseFailedScmActions(pr);

		AlertEvent alert = raised();
		Assertions.assertEquals(AlertTypeRegistry.SCM_REVIEW_ACTION_FAILED, alert.type());
		Assertions.assertEquals(2, alert.items().size());
		MatcherAssert.assertThat(alert.items().stream().map(AlertItem::text).toList(),
				Matchers.contains(Matchers.containsString("comment"),
						Matchers.containsString("Requesting changes")));
		Assertions.assertEquals(1.0, meterRegistry.get(PRScanAlerts.SCM_ACTION_METRIC)
				.tag("action", "decline").tag("outcome", "ok").counter().count());
		Assertions.assertEquals(1.0, meterRegistry.get(PRScanAlerts.SCM_ACTION_METRIC)
				.tag("action", "comment").tag("outcome", "failed").counter().count());
	}

	@Test
	public void testSuccessfulScmActionsRaiseNothing() {
		PRScanAlerts alerts = new PRScanAlerts(alertService, meterRegistry);
		alerts.recordScmAction(ScmAction.COMMENT, true);
		alerts.recordScmAction(ScmAction.APPROVE, true);
		alerts.raiseFailedScmActions(pr);

		BDDMockito.verifyNoInteractions(alertService);
	}

	@Test
	public void testWorksWithoutAlertServiceOrMetrics() {
		PRScanAlerts alerts = new PRScanAlerts(null, null);
		alerts.recordScmAction(ScmAction.APPROVE, false);
		alerts.raiseFailedScmActions(pr);
		alerts.scanIncomplete(pr, List.of("Betterleaks"));
	}
}
