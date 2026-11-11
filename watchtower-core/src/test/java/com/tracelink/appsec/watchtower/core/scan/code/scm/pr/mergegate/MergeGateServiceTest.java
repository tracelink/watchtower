package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PullRequestBypassEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PullRequestBypassRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;

/**
 * The merge gate view against the real Flyway schema (V079's columns and index included).
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@Transactional
public class MergeGateServiceTest {
	private static final String LABEL = "mergegate";
	private static final long NOW = Instant.parse("2026-10-14T12:00:00Z").toEpochMilli();
	private static final long HOUR = Duration.ofHours(1).toMillis();

	@Autowired
	private PRContainerRepository containers;
	@Autowired
	private PRScanRepository scans;
	@Autowired
	private PRViolationRepository violations;
	@Autowired
	private PullRequestBypassRepository bypasses;

	private ApiIntegrationService integrations;
	private MergeGateService service;

	@BeforeEach
	public void setup() {
		integrations = Mockito.mock(ApiIntegrationService.class);
		service = new MergeGateService(containers, scans, violations, bypasses, integrations,
				Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC));
	}

	@Test
	public void eachMergeIsCountedByWhatWatchtowerKnewWhenItHappened() {
		long merged = NOW - 2 * HOUR;
		// clean: the merged commit was scanned before the merge
		scan(merged("api", "1", merged, "aaa", false), "aaa", ScanStatus.DONE, merged - HOUR,
				false, false);
		// blocked, then bypassed before the merge
		PullRequestContainerEntity bypassed = merged("api", "2", merged, "bbb", false);
		PullRequestScanEntity blocked = scan(bypassed, "bbb", ScanStatus.DONE, merged - HOUR,
				true, false);
		bypass(bypassed, blocked, merged - HOUR / 2);
		// blocked, nothing bypassed
		scan(merged("api", "3", merged, "ccc", false), "ccc", ScanStatus.DONE, merged - HOUR,
				true, false);
		// an active bypass covered the findings when they were found, so the scan did not block
		PullRequestContainerEntity covered = merged("api", "4", merged, "ddd", false);
		PullRequestScanEntity coveredScan = scan(covered, "ddd", ScanStatus.DONE, merged - HOUR,
				false, true);
		bypass(covered, coveredScan, merged - 2 * HOUR);
		// queued when the merge was seen
		merged("web", "5", merged, "eee", true);
		// only an older commit scanned
		scan(merged("web", "6", merged, "fff", false), "old", ScanStatus.DONE, merged - HOUR,
				false, false);
		// never scanned
		merged("web", "7", merged, "ggg", false);
		// declined, and merged outside the window: neither counts
		closed("web", "8", PullRequestState.DECLINED, merged, null);
		merged("web", "9", NOW - Duration.ofDays(40).toMillis(), "hhh", false);

		MergeGateReport report = service.report(30);

		Assertions.assertEquals(7, report.merges());
		Assertions.assertEquals(1, report.scannedClean());
		Assertions.assertEquals(new MergeGateReport.Blocking(3, 2, 1),
				report.mergedWithBlockingFindings());
		Assertions.assertEquals(new MergeGateReport.BeforeScan(3, 1, 1, 0, 1),
				report.mergedBeforeScan());
		Assertions.assertEquals(6, report.pullRequests().size(), "every merge but the clean one");
		Assertions.assertFalse(report.truncated());
		MergeGateReport.RepositoryCount top = report.topRepositories().get(0);
		Assertions.assertEquals("web", top.repository());
		Assertions.assertEquals(3, top.ungated());
		Assertions.assertEquals(1, report.topRepositories().get(1).ungated(), "api's unbypassed");
	}

	@Test
	public void duplicateRowsOfOnePullRequestCountOnceWithTheirScansTogether() {
		long merged = NOW - HOUR;
		PullRequestContainerEntity older = merged("payments-api", "3", merged, "abc", false);
		merged("Payments-API", "3", merged + 1_000L, "abc", false);
		scan(older, "abc", ScanStatus.DONE, merged - HOUR, false, false);

		MergeGateReport report = service.report(7);

		Assertions.assertEquals(1, report.merges());
		Assertions.assertEquals(1, report.scannedClean());
	}

	@Test
	public void rowsLinkToTheirPullRequestInTheScm() {
		BBCloudIntegrationEntity bb = Mockito.mock(BBCloudIntegrationEntity.class);
		Mockito.when(bb.makePRLink("api", "1")).thenReturn("https://bitbucket.org/acme/api/pull-requests/1");
		Mockito.when(integrations.findByLabel(LABEL)).thenReturn(bb);
		merged("api", "1", NOW - HOUR, "abc", false);

		MergeGateReport.MergedPullRequestRow row = service.report(7).pullRequests().get(0);

		Assertions.assertEquals("https://bitbucket.org/acme/api/pull-requests/1", row.link());
		Assertions.assertEquals(MergeGateOutcome.NEVER_SCANNED, row.outcome());
		Assertions.assertEquals("Never scanned", row.reason());
	}

	@Test
	public void aReportIsReusedForAMinuteSoRefreshesDoNotRereadTheDatabase() {
		PRContainerRepository counted = Mockito.mock(PRContainerRepository.class);
		Mockito.when(counted.findClosedSince(Mockito.any(), Mockito.anyLong(), Mockito.any()))
				.thenReturn(java.util.List.of());
		PullRequestBypassRepository noBypasses = Mockito.mock(PullRequestBypassRepository.class);
		MutableClock clock = new MutableClock(NOW);
		MergeGateService cached = new MergeGateService(counted, scans, violations, noBypasses,
				integrations, clock);

		cached.report(7);
		cached.report(7);
		clock.advance(MergeGateService.CACHE_TTL.toMillis() + 1);
		cached.report(7);

		Mockito.verify(counted, Mockito.times(2)).findClosedSince(Mockito.any(),
				Mockito.anyLong(), Mockito.any());
	}

	/** A clock the test moves. */
	private static final class MutableClock extends Clock {
		private long millis;

		MutableClock(long millis) {
			this.millis = millis;
		}

		void advance(long by) {
			millis += by;
		}

		@Override
		public long millis() {
			return millis;
		}

		@Override
		public Instant instant() {
			return Instant.ofEpochMilli(millis);
		}

		@Override
		public java.time.ZoneId getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(java.time.ZoneId zone) {
			return this;
		}
	}

	@Test
	public void aWindowOutOfRangeIsRefused() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> service.report(0));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.report(MergeGateService.MAX_DAYS + 1));
	}

	private PullRequestContainerEntity merged(String repo, String prId, long at, String commit,
			boolean pending) {
		PullRequestContainerEntity pr = container(repo, prId);
		pr.recordClosed(PullRequestState.MERGED, at, commit, pending);
		return containers.saveAndFlush(pr);
	}

	private void closed(String repo, String prId, PullRequestState state, long at,
			String commit) {
		PullRequestContainerEntity pr = container(repo, prId);
		pr.recordClosed(state, at, commit, false);
		containers.saveAndFlush(pr);
	}

	private static PullRequestContainerEntity container(String repo, String prId) {
		PullRequestContainerEntity pr = new PullRequestContainerEntity();
		pr.setApiLabel(LABEL);
		pr.setRepoName(repo);
		pr.setPrId(prId);
		pr.setAuthor("alice");
		pr.setSourceBranch("feature");
		pr.setDestinationBranch("main");
		pr.setResolved(true);
		return pr;
	}

	private PullRequestScanEntity scan(PullRequestContainerEntity pr, String commit,
			ScanStatus status, long ended, boolean blocked, boolean bypassedFinding) {
		PullRequestScanEntity scan = new PullRequestScanEntity();
		scan.setContainer(pr);
		scan.setCommitHash(commit);
		scan.setSubmitDate(ended - 60_000L);
		scan.setEndDate(ended);
		scan.setStatus(status);
		scan.setBlocked(blocked);
		scan = scans.saveAndFlush(scan);
		if (bypassedFinding) {
			PullRequestViolationEntity v = new PullRequestViolationEntity();
			v.setScan(scan);
			v.setViolationName("hardcoded-key");
			v.setSeverity(RulePriority.HIGH);
			v.setFileName("src/App.java");
			v.setLineNum(1);
			v.setBypassed(true);
			violations.saveAndFlush(v);
		}
		return scan;
	}

	private void bypass(PullRequestContainerEntity pr, PullRequestScanEntity scan, long at) {
		PullRequestBypassEntity bypass = new PullRequestBypassEntity();
		bypass.setApiLabel(LABEL);
		bypass.setRepoName(pr.getRepoName());
		bypass.setPrId(pr.getPrId());
		bypass.setScanId(scan.getId());
		bypass.setBypassedBy("lead");
		bypass.setReason("Accepted risk");
		bypass.setCreatedAt(at);
		bypasses.saveAndFlush(bypass);
	}
}
