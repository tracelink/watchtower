package com.tracelink.appsec.module.betterleaks.alerting;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertItem;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanCompletedEvent;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanCompletedEvent.Finding;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.scan.RepoScanCompletedEvent;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;

public class BetterleaksAlertListenerTest {

	private static final long SCAN_ID = 77L;

	@RegisterExtension
	LogWatchExtension logWatcher = LogWatchExtension.forClass(BetterleaksAlertListener.class);

	private AlertService alertService;

	private AlertTypeRegistry registry;

	@BeforeEach
	public void setup() {
		alertService = BDDMockito.mock(AlertService.class);
		registry = new AlertTypeRegistry();
	}

	private BetterleaksAlertListener listener(String publicUrl, Executor executor) {
		return new BetterleaksAlertListener(alertService, registry, publicUrl, executor);
	}

	private static PullRequest pullRequest() {
		PullRequest pr = new PullRequest("bb-cloud");
		pr.setRepoName("payments");
		pr.setPrId("42");
		pr.setAuthor("alice");
		return pr;
	}

	private static Finding secret(long id, String file, int line, RulePriority priority,
			boolean isNew, boolean blocking) {
		return new Finding(id, "Betterleaks: github-pat", priority, file, line, isNew, blocking);
	}

	private static PRScanCompletedEvent event(Finding... findings) {
		return new PRScanCompletedEvent(SCAN_ID, pullRequest(), List.of(findings));
	}

	private AlertEvent raised() {
		ArgumentCaptor<AlertEvent> captor = ArgumentCaptor.forClass(AlertEvent.class);
		BDDMockito.verify(alertService).raise(captor.capture());
		return captor.getValue();
	}

	@Test
	public void testRegistersSecretDetectedWithAPriorityFilter() {
		listener(null, Runnable::run);

		Assertions.assertTrue(registry.get(BetterleaksAlertListener.SECRET_DETECTED)
				.orElseThrow().supportsPriorityFilter());
	}

	@Test
	public void testRaisesOneAlertWithEveryNewSecretOfTheScan() {
		listener("https://watchtower.example.com/", Runnable::run).onScanCompleted(event(
				secret(1, "src/config.yml", 12, RulePriority.HIGH, true, true),
				secret(2, "src/app.env", 3, RulePriority.MEDIUM, true, false)));

		AlertEvent alert = raised();
		Assertions.assertEquals(BetterleaksAlertListener.SECRET_DETECTED, alert.type());
		Assertions.assertEquals("bb-cloud", alert.apiLabel());
		Assertions.assertEquals("payments", alert.repoName());
		MatcherAssert.assertThat(alert.title(), Matchers.containsString("pull request #42"));
		MatcherAssert.assertThat(alert.title(), Matchers.containsString("alice"));
		Assertions.assertEquals("https://watchtower.example.com/scan/report/77", alert.link());
		Assertions.assertEquals(List.of(
				"High · github-pat · src/config.yml:12 · blocking",
				"Medium · github-pat · src/app.env:3 · not blocking"),
				alert.items().stream().map(AlertItem::text).toList());
		Assertions.assertEquals(RulePriority.HIGH, alert.items().get(0).priority());
	}

	@Test
	public void testIgnoresOldLinesAndOtherModulesFindings() {
		listener(null, Runnable::run).onScanCompleted(event(
				secret(1, "src/config.yml", 12, RulePriority.HIGH, false, false),
				new Finding(2, "Regex: AWS key", RulePriority.HIGH, "a.txt", 1, true, true),
				new Finding(3, null, RulePriority.HIGH, "b.txt", 1, true, true)));

		BDDMockito.verifyNoInteractions(alertService);
	}

	@Test
	public void testDedupeKeyIsStablePerPullRequestRuleFileAndLine() {
		BetterleaksAlertListener listener = listener(null, Runnable::run);
		listener.onScanCompleted(event(secret(1, "a.yml", 5, RulePriority.HIGH, true, true)));
		listener.onScanCompleted(event(secret(9, "a.yml", 5, RulePriority.MEDIUM, true, false),
				secret(10, "a.yml", 6, RulePriority.HIGH, true, true)));

		ArgumentCaptor<AlertEvent> captor = ArgumentCaptor.forClass(AlertEvent.class);
		BDDMockito.verify(alertService, BDDMockito.times(2)).raise(captor.capture());
		AlertEvent first = captor.getAllValues().get(0);
		AlertEvent second = captor.getAllValues().get(1);
		// A rescan of the same line (new violation id, new priority) must not alert again.
		Assertions.assertEquals(first.items().get(0).dedupeKey(),
				second.items().get(0).dedupeKey());
		Assertions.assertNotEquals(second.items().get(0).dedupeKey(),
				second.items().get(1).dedupeKey());
		Assertions.assertEquals(first.threadKey(), second.threadKey());
		Assertions.assertEquals(BetterleaksAlertListener.threadKey(pullRequest()),
				first.threadKey());
	}

	@Test
	public void testNoLinkWithoutAPublicUrl() {
		listener("  ", Runnable::run)
				.onScanCompleted(event(secret(1, "a.yml", 5, RulePriority.HIGH, true, true)));

		Assertions.assertNull(raised().link());
	}

	@Test
	public void testRaisesOnTheListenersExecutorNotTheScanThread() {
		List<Runnable> queued = new ArrayList<>();
		listener(null, queued::add)
				.onScanCompleted(event(secret(1, "a.yml", 5, RulePriority.HIGH, true, true)));

		BDDMockito.verifyNoInteractions(alertService);
		Assertions.assertEquals(1, queued.size());
		queued.get(0).run();
		BDDMockito.verify(alertService).raise(BDDMockito.any());
	}

	@Test
	public void testAFullQueueDropsTheAlertWithAWarningAndNeverThrows() {
		listener(null, task -> {
			throw new RejectedExecutionException("full");
		}).onScanCompleted(event(secret(1, "a.yml", 5, RulePriority.HIGH, true, true)));

		BDDMockito.verifyNoInteractions(alertService);
		MatcherAssert.assertThat(logWatcher.getFormattedMessages(),
				Matchers.hasItem(Matchers.containsString("scan 77")));
	}

	@Test
	public void testUnknownPriorityIsShownNotDropped() {
		listener(null, Runnable::run)
				.onScanCompleted(event(secret(1, "a.yml", 5, null, true, false)));

		Assertions.assertEquals("Unknown · github-pat · a.yml:5 · not blocking",
				raised().items().get(0).text());
	}

	private static RepoScanReport.Finding repoFinding(String rule) {
		return new RepoScanReport.Finding(rule, "High", "config/app.yml", 3, "secret found",
				"fp1", true, true);
	}

	@Test
	public void newSecretsInARepositoryScanRaiseOneAlertWithAReportLink() {
		listener("https://watchtower.example.com/", Runnable::run)
				.onRepoScanCompleted(new RepoScanCompletedEvent(9, "bb-cloud", "payments",
						"main", "abc", false, List.of(repoFinding("Betterleaks: github-pat"),
								repoFinding("pmd-unused"))));

		AlertEvent alert = raised();
		Assertions.assertEquals("New secrets in payments (main)", alert.title());
		Assertions.assertEquals("https://watchtower.example.com/reposcan/report/9", alert.link());
		Assertions.assertEquals(1, alert.items().size());
		Assertions.assertEquals("High · github-pat · config/app.yml:3",
				alert.items().get(0).text());
	}

	@Test
	public void aBaselineOrNonSecretRepositoryScanRaisesNothing() {
		BetterleaksAlertListener listener = listener(null, Runnable::run);
		listener.onRepoScanCompleted(new RepoScanCompletedEvent(9, "bb-cloud", "payments",
				"main", "abc", true, List.of()));
		listener.onRepoScanCompleted(new RepoScanCompletedEvent(10, "bb-cloud", "payments",
				"main", "abc", false, List.of(repoFinding("pmd-unused"))));

		BDDMockito.verifyNoInteractions(alertService);
	}
}
