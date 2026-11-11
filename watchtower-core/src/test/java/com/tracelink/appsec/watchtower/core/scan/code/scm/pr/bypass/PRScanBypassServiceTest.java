package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanSubmitResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.verification.ILiveVerifier;
import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

public class PRScanBypassServiceTest {

	private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");
	private static final String API_LABEL = "bb";
	private static final String REPO = "payments";
	private static final String PR_ID = "17";
	private static final String REASON = "Hotfix for an outage; test fixture key";

	private PullRequestBypassRepository bypassRepository;
	private PRScanRepository scanRepository;
	private ApiIntegrationService apiService;
	private IScmApi scmApi;
	private AlertService alertService;
	private AlertTypeRegistry registry;
	private ILiveVerifier verifier;
	private PRScanningService scanningService;
	private ObjectProvider<ILiveVerifier> verifiers;
	private PRScanBypassService service;
	private SimpleMeterRegistry meters;

	private PullRequestContainerEntity container;
	private final List<PullRequestScanEntity> scans = new ArrayList<>();
	private final List<PullRequestBypassEntity> active = new ArrayList<>();

	@BeforeEach
	@SuppressWarnings("unchecked")
	public void setup() {
		bypassRepository = BDDMockito.mock(PullRequestBypassRepository.class);
		scanRepository = BDDMockito.mock(PRScanRepository.class);
		apiService = BDDMockito.mock(ApiIntegrationService.class);
		scmApi = BDDMockito.mock(IScmApi.class);
		alertService = BDDMockito.mock(AlertService.class);
		registry = new AlertTypeRegistry();
		verifier = BDDMockito.mock(ILiveVerifier.class);
		scanningService = BDDMockito.mock(PRScanningService.class);
		verifiers = BDDMockito.mock(ObjectProvider.class);
		ObjectProvider<PRScanningService> scanningServices = BDDMockito.mock(ObjectProvider.class);
		BDDMockito.when(verifiers.getIfUnique()).thenReturn(null);
		BDDMockito.when(scanningServices.getIfAvailable()).thenReturn(scanningService);

		ApiIntegrationEntity apiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(apiService.findByLabel(API_LABEL)).thenReturn(apiEntity);
		BDDMockito.when(apiEntity.createApi()).thenReturn(scmApi);
		BDDMockito.when(scmApi.approvePR(BDDMockito.any())).thenReturn(true);
		BDDMockito.when(scmApi.sendComment(BDDMockito.any(), BDDMockito.anyString()))
				.thenReturn(true);
		BDDMockito.when(bypassRepository.save(BDDMockito.any()))
				.thenAnswer(invocation -> invocation.getArgument(0));
		BDDMockito.when(bypassRepository.findActive(API_LABEL, REPO, PR_ID)).thenReturn(active);

		container = new PullRequestContainerEntity();
		container.setApiLabel(API_LABEL);
		container.setRepoName(REPO);
		container.setPrId(PR_ID);
		ReflectionTestUtils.setField(container, "scans", scans);

		meters = new SimpleMeterRegistry();
		service = new PRScanBypassService(bypassRepository, scanRepository, apiService,
				alertService, registry, verifiers, scanningServices, meters,
				"https://watchtower.example.invalid/", Clock.fixed(NOW, ZoneOffset.UTC));
	}

	private double counted(String action) {
		return meters.counter(PRScanBypassService.METRIC, "action", action).count();
	}

	@Test
	public void testBypassAndRevokeAreCounted() throws Exception {
		scan(5, true, violation(1, "AWS Key", "a.yml"));
		service.bypass(5, "alice", REASON);
		activeBypass("alice", REASON, 1000);
		BDDMockito.when(scanningService.doPullRequestScan(BDDMockito.any()))
				.thenReturn(PRScanSubmitResult.QUEUED);
		service.revoke(5, "bob");

		Assertions.assertEquals(1.0, counted("bypass"));
		Assertions.assertEquals(1.0, counted("revoke"));
	}

	@Test
	public void selectedRemoteAssessmentCannotBeApprovedByLocalOnlyBypass() throws Exception {
		var scan = scan(5, true, violation(1, "local", "a.yml"));
		scan.setRemoteAssessmentState("PENDING");
		var remote = BDDMockito.mock(com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.class);
		BDDMockito.when(remote.bypassFindings(5)).thenReturn(Set.of(new BypassedFinding("AWS policy", "src/app.py")));
		ReflectionTestUtils.setField(service, "remoteAssessments", remote);
		Assertions.assertFalse(service.bypass(5, "alice", REASON));
		BDDMockito.verify(apiService, BDDMockito.never()).findByLabel(BDDMockito.anyString());
		BDDMockito.verify(bypassRepository).save(BDDMockito.argThat(b -> b.getFindings().contains(new BypassedFinding("AWS policy", "src/app.py"))));
	}

	@Test
	public void testRefusedBypassIsNotCounted() {
		scan(5, false, violation(1, "AWS Key", "a.yml"));

		Assertions.assertThrows(PRScanBypassException.class,
				() -> service.bypass(5, "alice", REASON));
		Assertions.assertEquals(0.0, counted("bypass"));
	}

	private PullRequestScanEntity scan(long id, boolean blocked, PullRequestViolationEntity... vs) {
		PullRequestScanEntity scan = new PullRequestScanEntity();
		ReflectionTestUtils.setField(scan, "id", id);
		scan.setContainer(container);
		scan.setBlocked(blocked);
		scan.setCommitHash("commit-" + id);
		ReflectionTestUtils.setField(scan, "violations", new ArrayList<>(List.of(vs)));
		scans.add(scan);
		BDDMockito.when(scanRepository.findById(id)).thenReturn(scan);
		return scan;
	}

	private static PullRequestViolationEntity violation(long id, String rule, String file) {
		PullRequestViolationEntity violation = new PullRequestViolationEntity();
		ReflectionTestUtils.setField(violation, "id", id);
		violation.setViolationName(rule);
		violation.setFileName(file);
		return violation;
	}

	private PullRequestBypassEntity activeBypass(String by, String reason, long createdAt,
			BypassedFinding... findings) {
		PullRequestBypassEntity bypass = new PullRequestBypassEntity();
		bypass.setApiLabel(API_LABEL);
		bypass.setRepoName(REPO);
		bypass.setPrId(PR_ID);
		bypass.setBypassedBy(by);
		bypass.setReason(reason);
		bypass.setCreatedAt(createdAt);
		bypass.setFindings(Set.of(findings));
		active.add(bypass);
		return bypass;
	}

	private void givenLive(long violationId) {
		BDDMockito.when(verifiers.getIfUnique()).thenReturn(verifier);
		BDDMockito.when(verifier.getStatuses(BDDMockito.any()))
				.thenReturn(Map.of(violationId, LiveVerificationStatus.LIVE));
	}

	private PullRequestBypassEntity savedBypass() {
		ArgumentCaptor<PullRequestBypassEntity> captor =
				ArgumentCaptor.forClass(PullRequestBypassEntity.class);
		BDDMockito.verify(bypassRepository).save(captor.capture());
		return captor.getValue();
	}

	private String postedComment() {
		ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(scmApi).sendComment(BDDMockito.any(), captor.capture());
		return captor.getValue();
	}

	private void assertRefused(Runnable action, String messagePart) {
		PRScanBypassException e = Assertions.assertThrows(PRScanBypassException.class,
				action::run);
		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString(messagePart));
	}

	// --- bypass ---

	@Test
	public void testRegistersAlertType() {
		Assertions.assertTrue(registry.get(PRScanBypassService.PR_BYPASSED).isPresent());
	}

	@Test
	public void testBypassSavesEveryFindingOfTheScan() {
		scan(5, true, violation(1, "AWS Key", "a.yml"), violation(2, "AWS Key", "a.yml"),
				violation(3, "Token", "b.sh"));

		service.bypass(5, "alice", "  " + REASON + "  ");

		PullRequestBypassEntity saved = savedBypass();
		Assertions.assertEquals(API_LABEL, saved.getApiLabel());
		Assertions.assertEquals(REPO, saved.getRepoName());
		Assertions.assertEquals(PR_ID, saved.getPrId());
		Assertions.assertEquals(5, saved.getScanId());
		Assertions.assertEquals("commit-5", saved.getCommitHash());
		Assertions.assertEquals("alice", saved.getBypassedBy());
		Assertions.assertEquals(REASON, saved.getReason());
		Assertions.assertEquals(NOW.toEpochMilli(), saved.getCreatedAt());
		Assertions.assertEquals(Set.of(new BypassedFinding("AWS Key", "a.yml"),
				new BypassedFinding("Token", "b.sh")), saved.getFindings());
	}

	@Test
	public void testBypassApprovesTheBypassedCommitAndComments() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		Assertions.assertTrue(service.bypass(5, "alice", REASON));

		ArgumentCaptor<PullRequest> pr = ArgumentCaptor.forClass(PullRequest.class);
		BDDMockito.verify(scmApi).approvePR(pr.capture());
		Assertions.assertEquals(API_LABEL, pr.getValue().getApiLabel());
		Assertions.assertEquals(REPO, pr.getValue().getRepoName());
		Assertions.assertEquals(PR_ID, pr.getValue().getPrId());
		Assertions.assertEquals("commit-5", pr.getValue().getCommitHash());
		Assertions.assertEquals("Blocking bypassed by alice: `" + REASON
				+ "`. New blocking findings still block.", postedComment());
	}

	@Test
	public void testDeclinedRequestIsAnsweredOnThePullRequestWithItsNote() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		service.commentDeclined(5, "lead", "Fix it instead");

		Assertions.assertEquals("Bypass request declined by lead: `Fix it instead`.",
				postedComment());
	}

	@Test
	public void testDeclinedRequestWithoutANoteIsStillAnswered() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		service.commentDeclined(5, "lead", null);

		Assertions.assertEquals("Bypass request declined by lead.", postedComment());
	}

	@Test
	public void testBypassCommentKeepsReasonOnOneLine() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		service.bypass(5, "alice", "line one\n\n### line two");

		Assertions.assertEquals("Blocking bypassed by alice: `line one ### line two`."
				+ " New blocking findings still block.", postedComment());
	}

	@Test
	public void testUserTextCannotAddLinksOrFormattingToTheComment() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		service.bypass(5, "a_lice*", "[Watchtower CI](http://evil.example) `x` http://evil.example");

		Assertions.assertEquals("Blocking bypassed by a\\_lice\\*:"
				+ " `[Watchtower CI](http://evil.example) 'x' http://evil.example`."
				+ " New blocking findings still block.", postedComment());
	}

	@Test
	public void testAlertKeepsTheReasonPlain() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		service.bypass(5, "alice", REASON);

		ArgumentCaptor<AlertEvent> captor = ArgumentCaptor.forClass(AlertEvent.class);
		BDDMockito.verify(alertService).raise(captor.capture());
		MatcherAssert.assertThat(captor.getValue().items().get(0).text(),
				Matchers.not(Matchers.containsString("`")));
	}

	@Test
	public void testBypassRaisesAlert() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		service.bypass(5, "alice", REASON);

		ArgumentCaptor<AlertEvent> captor = ArgumentCaptor.forClass(AlertEvent.class);
		BDDMockito.verify(alertService).raise(captor.capture());
		AlertEvent event = captor.getValue();
		Assertions.assertEquals(PRScanBypassService.PR_BYPASSED, event.type());
		Assertions.assertEquals(API_LABEL, event.apiLabel());
		Assertions.assertEquals(REPO, event.repoName());
		Assertions.assertEquals("https://watchtower.example.invalid/scan/report/5", event.link());
		MatcherAssert.assertThat(event.title(), Matchers.containsString("#" + PR_ID));
		Assertions.assertEquals(1, event.items().size());
		MatcherAssert.assertThat(event.items().get(0).text(),
				Matchers.allOf(Matchers.containsString("alice"), Matchers.containsString(REASON)));
	}

	@Test
	public void testBypassRefusesBlankReason() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		assertRefused(() -> service.bypass(5, "alice", "   "), "reason");
		BDDMockito.verify(bypassRepository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testBypassRefusesOverlongReason() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		assertRefused(() -> service.bypass(5, "alice",
				"r".repeat(PullRequestBypassEntity.MAX_REASON_LENGTH + 1)), "1000");
	}

	@Test
	public void testBypassAcceptsReasonAtLimit() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		service.bypass(5, "alice", "r".repeat(PullRequestBypassEntity.MAX_REASON_LENGTH));

		Assertions.assertEquals(PullRequestBypassEntity.MAX_REASON_LENGTH,
				savedBypass().getReason().length());
	}

	@Test
	public void testBypassRefusesUnknownScan() {
		assertRefused(() -> service.bypass(99, "alice", REASON), "Unknown");
	}

	@Test
	public void testBypassRefusesScanThatDidNotBlock() {
		scan(5, false, violation(1, "AWS Key", "a.yml"));

		assertRefused(() -> service.bypass(5, "alice", REASON), "not blocking");
	}

	@Test
	public void testBypassRefusesOlderScan() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));
		scan(6, true, violation(2, "AWS Key", "a.yml"));

		assertRefused(() -> service.bypass(5, "alice", REASON), "latest");
	}

	@Test
	public void testBypassRefusesResolvedPullRequest() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));
		container.setResolved(true);

		assertRefused(() -> service.bypass(5, "alice", REASON), "closed");
	}

	@Test
	public void testBypassRefusesWhileAnyFindingOfThePrIsLive() {
		scan(4, true, violation(1, "AWS Key", "old.yml"));
		scan(5, true, violation(2, "AWS Key", "a.yml"));
		givenLive(1);

		assertRefused(() -> service.bypass(5, "alice", REASON), "Rotate");
		BDDMockito.verify(bypassRepository, BDDMockito.never()).save(BDDMockito.any());
		BDDMockito.verify(scmApi, BDDMockito.never()).approvePR(BDDMockito.any());
	}

	@Test
	public void testBypassChecksLiveStatusOfEveryScanOfThePr() {
		scan(4, true, violation(1, "AWS Key", "old.yml"));
		scan(5, true, violation(2, "AWS Key", "a.yml"));
		BDDMockito.when(verifiers.getIfUnique()).thenReturn(verifier);
		BDDMockito.when(verifier.getStatuses(BDDMockito.any()))
				.thenReturn(Map.of(1L, LiveVerificationStatus.INVALID));

		service.bypass(5, "alice", REASON);

		BDDMockito.verify(verifier).getStatuses(Set.of(1L, 2L));
	}

	@Test
	public void testBypassRefusedWhenLiveStatusCannotBeRead() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));
		BDDMockito.when(verifiers.getIfUnique()).thenReturn(verifier);
		BDDMockito.when(verifier.getStatuses(BDDMockito.any()))
				.thenThrow(new IllegalStateException("db down"));

		assertRefused(() -> service.bypass(5, "alice", REASON), "verification");
	}

	@Test
	public void testBypassKeptWhenScmUpdateFails() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));
		BDDMockito.when(scmApi.approvePR(BDDMockito.any())).thenReturn(false);

		Assertions.assertFalse(service.bypass(5, "alice", REASON));
		savedBypass();
		BDDMockito.verify(alertService).raise(BDDMockito.any());
	}

	@Test
	public void testBypassKeptWhenScmThrows() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));
		BDDMockito.when(scmApi.approvePR(BDDMockito.any()))
				.thenThrow(new IllegalStateException("boom"));

		Assertions.assertFalse(service.bypass(5, "alice", REASON));
		savedBypass();
	}

	@Test
	public void testBypassKeptWhenIntegrationIsGone() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));
		BDDMockito.when(apiService.findByLabel(API_LABEL)).thenReturn(null);

		Assertions.assertFalse(service.bypass(5, "alice", REASON));
		savedBypass();
	}

	@Test
	public void testBypassKeptWhenAlertFails() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));
		BDDMockito.doThrow(new IllegalStateException("alerts down")).when(alertService)
				.raise(BDDMockito.any());

		Assertions.assertTrue(service.bypass(5, "alice", REASON));
		savedBypass();
	}

	// --- revoke ---

	@Test
	public void testRevokeEndsEveryActiveBypassAndRescans() throws Exception {
		scan(5, false, violation(1, "AWS Key", "a.yml"));
		PullRequestBypassEntity first = activeBypass("alice", REASON, 1000);
		PullRequestBypassEntity second = activeBypass("carol", "other", 2000);
		BDDMockito.when(scanningService.doPullRequestScan(BDDMockito.any()))
				.thenReturn(PRScanSubmitResult.QUEUED);

		Assertions.assertTrue(service.revoke(5, "bob"));

		Assertions.assertTrue(first.isRevoked());
		Assertions.assertTrue(second.isRevoked());
		Assertions.assertEquals("bob", first.getRevokedBy());
		Assertions.assertEquals(NOW.toEpochMilli(), first.getRevokedAt());
		BDDMockito.verify(bypassRepository).saveAll(List.of(first, second));
		Assertions.assertEquals("Blocking bypass revoked by bob. Watchtower is rescanning;"
				+ " blocking findings block again.", postedComment());
		ArgumentCaptor<PullRequest> pr = ArgumentCaptor.forClass(PullRequest.class);
		BDDMockito.verify(scanningService).doPullRequestScan(pr.capture());
		Assertions.assertEquals(PR_ID, pr.getValue().getPrId());
		Assertions.assertEquals(REPO, pr.getValue().getRepoName());
		Assertions.assertEquals(API_LABEL, pr.getValue().getApiLabel());
	}

	@Test
	public void testRevokeRefusedWithoutActiveBypass() {
		scan(5, false, violation(1, "AWS Key", "a.yml"));

		assertRefused(() -> service.revoke(5, "bob"), "No active bypass");
	}

	@Test
	public void testRevokeRefusesUnknownScan() {
		assertRefused(() -> service.revoke(99, "bob"), "Unknown");
	}

	@Test
	public void testRevokeKeptWhenRescanCannotBeQueued() throws Exception {
		scan(5, false, violation(1, "AWS Key", "a.yml"));
		PullRequestBypassEntity bypass = activeBypass("alice", REASON, 1000);
		BDDMockito.when(scanningService.doPullRequestScan(BDDMockito.any()))
				.thenThrow(new ScanRejectedException("quiesced"));

		Assertions.assertFalse(service.revoke(5, "bob"));
		Assertions.assertTrue(bypass.isRevoked());
	}

	// --- activeFor ---

	@Test
	public void testActiveForIsEmptyWithoutBypass() {
		Assertions.assertEquals(Optional.empty(), service.activeFor(API_LABEL, REPO, PR_ID));
	}

	@Test
	public void testActiveForUnitesFindingsAndNamesTheNewest() {
		activeBypass("carol", "newest", 2000, new BypassedFinding("Token", "b.sh"));
		activeBypass("alice", "older", 1000, new BypassedFinding("AWS Key", "a.yml"));

		ActiveBypass bypass = service.activeFor(API_LABEL, REPO, PR_ID).orElseThrow();

		Assertions.assertEquals("carol", bypass.bypassedBy());
		Assertions.assertEquals("newest", bypass.reason());
		Assertions.assertEquals(2000, bypass.createdAt());
		Assertions.assertTrue(bypass.covers("Token", "b.sh"));
		Assertions.assertTrue(bypass.covers("AWS Key", "a.yml"));
		Assertions.assertFalse(bypass.covers("AWS Key", "b.sh"));
		Assertions.assertFalse(bypass.covers("Other", "a.yml"));
	}

	@Test
	public void testActiveForIsEmptyWhenLookupFails() {
		BDDMockito.when(bypassRepository.findActive(API_LABEL, REPO, PR_ID))
				.thenThrow(new IllegalStateException("db down"));

		Assertions.assertEquals(Optional.empty(), service.activeFor(API_LABEL, REPO, PR_ID));
	}

	// --- stateFor ---

	@Test
	public void testStateForBlockedLatestScanAllowsBypass() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));

		BypassState state = service.stateFor(5, true);

		Assertions.assertTrue(state.blocked());
		Assertions.assertTrue(state.canBypass());
		Assertions.assertNull(state.refusal());
		Assertions.assertFalse(state.isActive());
	}

	@Test
	public void testStateForLiveSecretExplainsRefusal() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));
		givenLive(1);

		BypassState state = service.stateFor(5, true);

		Assertions.assertTrue(state.blocked());
		Assertions.assertFalse(state.canBypass());
		MatcherAssert.assertThat(state.refusal(), Matchers.containsString("Rotate"));
	}

	@Test
	public void testStateForViewerWhoCannotBypassSkipsTheLiveCheck() {
		scan(5, true, violation(1, "AWS Key", "a.yml"));
		givenLive(1);

		BypassState state = service.stateFor(5, false);

		Assertions.assertTrue(state.blocked());
		Assertions.assertNull(state.refusal());
		BDDMockito.verify(verifier, BDDMockito.never()).getStatuses(BDDMockito.any());
	}

	@Test
	public void testStateForNonBlockingScanOffersNothing() {
		scan(5, false, violation(1, "AWS Key", "a.yml"));

		BypassState state = service.stateFor(5, true);

		Assertions.assertFalse(state.blocked());
		Assertions.assertFalse(state.canBypass());
	}

	@Test
	public void testStateForShowsActiveBypass() {
		scan(5, false, violation(1, "AWS Key", "a.yml"));
		activeBypass("alice", REASON, 1000, new BypassedFinding("AWS Key", "a.yml"));

		BypassState state = service.stateFor(5, true);

		Assertions.assertTrue(state.isActive());
		Assertions.assertEquals("alice", state.active().bypassedBy());
	}

	private static PullRequestViolationEntity blockingNew(long id, String rule, String file) {
		PullRequestViolationEntity v = violation(id, rule, file);
		v.setBlocking(true);
		v.setNewViolation(true);
		return v;
	}

	@Test
	public void testStateForScanWhoseBlockingIsAllBypassedIsNoLongerShownAsBlocked() {
		// The scan was blocked, then bypassed without a rescan: its own flag is still set
		scan(5, true, blockingNew(1, "AWS Key", "a.yml"), blockingNew(2, "Token", "b.sh"));
		activeBypass("alice", REASON, 1000, new BypassedFinding("AWS Key", "a.yml"),
				new BypassedFinding("Token", "b.sh"));

		BypassState state = service.stateFor(5, true);

		Assertions.assertFalse(state.blocked());
		Assertions.assertTrue(state.isActive());
		Assertions.assertFalse(state.canBypass());
	}

	@Test
	public void testStateForScanStaysBlockedWhenAFindingIsNotCoveredByTheBypass() {
		scan(5, true, blockingNew(1, "AWS Key", "a.yml"), blockingNew(2, "Token", "b.sh"));
		activeBypass("alice", REASON, 1000, new BypassedFinding("AWS Key", "a.yml"));

		BypassState state = service.stateFor(5, true);

		Assertions.assertTrue(state.blocked());
		Assertions.assertTrue(state.isActive());
	}

	@Test
	public void testStateForRemoteReviewBlockingIsNotClearedByALocalBypass() {
		PullRequestScanEntity scan = scan(5, true, blockingNew(1, "AWS Key", "a.yml"));
		scan.setRemoteAssessmentState("COMPLETE");
		activeBypass("alice", REASON, 1000, new BypassedFinding("AWS Key", "a.yml"));

		Assertions.assertTrue(service.stateFor(5, true).blocked());
	}

	@Test
	public void testStateForUnknownScanOffersNothing() {
		BypassState state = service.stateFor(99, true);

		Assertions.assertFalse(state.blocked());
		Assertions.assertFalse(state.canBypass());
		Assertions.assertFalse(state.isActive());
	}
}
